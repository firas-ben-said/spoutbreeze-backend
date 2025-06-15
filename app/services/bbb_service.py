import time
import json
import requests
from urllib.parse import urlencode
from typing import Dict, Any, Union, Optional
from fastapi import HTTPException
from fastapi.responses import RedirectResponse
from datetime import datetime, timedelta


from app.config.settings import get_settings
from app.utils.bbb_helpers import parse_xml_response, generate_checksum
from app.models.bbb_schemas import (
    CreateMeetingRequest,
    JoinMeetingRequest,
    EndMeetingRequest,
    GetMeetingInfoRequest,
    IsMeetingRunningRequest,
    GetRecordingRequest,
)
from app.models.bbb_models import BbbMeeting
from app.models.event.event_models import Event
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete  # noqa: F401
from uuid import UUID
from app.config.logger_config import logger
from app.services.twitch_service import TwitchService
from app.config.twitch_irc import TwitchIRCClient


class BBBService:
    def __init__(self):
        self.settings = get_settings()
        self.server_base_url = self.settings.bbb_server_base_url
        self.secret = self.settings.bbb_secret
        self.twitch_client = None

    async def create_meeting(
        self,
        request: CreateMeetingRequest,
        user_id: UUID,
        db: AsyncSession,
        event_id: Optional[UUID] = None,
        enable_twitch: bool = False,
    ) -> Dict[str, Any]:
        """Create a new BBB meeting."""
        # Generate a meeting ID if not provided
        if not request.meeting_id:
            request.meeting_id = f"meeting-{int(time.time())}"

        # Check if meeting ID already exists in the database
        stmt = select(BbbMeeting).where(BbbMeeting.meeting_id == request.meeting_id)
        result = await db.execute(stmt)
        existing_meeting = result.scalars().first()

        if existing_meeting:
            raise HTTPException(
                status_code=400,
                detail=f"Meeting ID '{request.meeting_id}' is already in use. Please choose a different meeting ID.",
            )

        # Prepare parameters for BBB API
        params = {
            "name": request.name,
            "meetingID": request.meeting_id,
            "attendeePW": request.attendee_pw,
            "moderatorPW": request.moderator_pw,
            "welcome": request.welcome,
            "maxParticipants": request.max_participants,
            "duration": request.duration,
            "record": request.record,
            "autoStartRecording": request.auto_start_recording,
            "allowStartStopRecording": request.allow_start_stop_recording,
            "moderatorOnlyMessage": request.moderator_only_message,
            "logo": request.logo_url,
            "pluginManifests": request.pluginManifests,
            # Add call back url for meeting end
            "meta_endCallbackUrl": (
                f"{self.settings.api_base_url}/api/bbb/callback/meeting-ended?event_id={event_id}"
                if event_id
                else f"{self.settings.api_base_url}/api/bbb/callback/meeting-ended"
            ),
            # "meta_streamEndpointsUrl": f"{self.settings.api_base_url}/api/stream-endpoints/",
            # "meta_streamEndpointsUrl": f"https://6f13-102-157-168-239.ngrok-free.app/api/bbb/proxy/stream-endpoints",
            # Uncomment the following line if you want to use ngrok for testing
            # "meta_endCallbackUrl": (
            #     f"https://0bd0-2c0f-4280-6000-433c-a7c0-a658-ce43-3831.ngrok-free.app/api/bbb/callback/meeting-ended?event_id={event_id}"
            #     if event_id
            #     else "https://0bd0-2c0f-4280-6000-433c-a7c0-a658-ce43-3831.ngrok-free.app/api/bbb/callback/meeting-ended"
            # ),
        }

        # Remove None values
        params = {k: v for k, v in params.items() if v is not None}

        response = self._call_bbb_api("create", params)
        # Check if the meeting was created successfully
        if response.get("returncode") != "SUCCESS":
            raise HTTPException(
                status_code=400,
                detail=f"Failed to create meeting: {response.get('messageKey')}",
            )

        # Connect to Twitch if requested and token available
        twitch_status = {"enabled": False}
        if enable_twitch:
            try:
                twitch_service = TwitchService()

                if await twitch_service.is_token_valid():
                    self.twitch_client = TwitchIRCClient()

                    connected = await self.twitch_client.connect_for_meeting()
                    if connected:
                        twitch_status = {
                            "enabled": True,
                            "status": "connected",
                            "channel": self.twitch_client.channel,
                        }
                        logger.info(
                            f"[BBB] Meeting {response.get('meetingID')} created with Twitch chat"
                        )
                    else:
                        twitch_status = {
                            "enabled": False,
                            "status": "failed",
                            "error": "Failed to connect to Twitch IRC",
                        }
                else:
                    twitch_status = {
                        "enabled": False,
                        "status": "no_token",
                        "error": "No valid Twitch token available",
                    }
            except Exception as e:
                logger.error(f"[BBB] Twitch connection error: {e}")
                twitch_status = {
                    "enabled": False,
                    "status": "error",
                    "error": str(e),
                }

        # Save meeting details to the database
        meeting = BbbMeeting(
            meeting_id=response.get("meetingID"),
            internal_meeting_id=response.get("internalMeetingID"),
            parent_meeting_id=response.get("parentMeetingID"),
            attendee_pw=response.get("attendeePW"),
            moderator_pw=response.get("moderatorPW"),
            create_time=response.get("createTime"),
            voice_bridge=response.get("voiceBridge"),
            dial_number=response.get("dialNumber"),
            has_user_joined=response.get("hasUserJoined"),
            duration=response.get("duration"),
            has_been_forcibly_ended=response.get("hasBeenForciblyEnded"),
            message_key=response.get("messageKey"),
            message=response.get("message"),
            user_id=user_id,
        )
        db.add(meeting)
        await db.commit()
        await db.refresh(meeting)
        logger.info(f"Meeting created with ID: {meeting.meeting_id} by user: {user_id}")

        # Add Twitch status to response
        response["twitch"] = twitch_status

        return response

    def join_meeting(
        self,
        request: JoinMeetingRequest,
    ) -> Union[Dict[str, Any], RedirectResponse]:
        """Join a BBB meeting."""
        # Create base params
        processed_params = {}

        # Process parameters
        for key, value in {
            "meetingID": request.meeting_id,
            "fullName": request.full_name,
            "password": request.password,
            "userID": request.user_id,
        }.items():
            if value is not None:
                processed_params[key] = value

        # Handle pluginManifests separately
        if request.pluginManifests:
            # Convert Pydantic models to dict first, then to JSON string
            plugin_dicts = [
                plugin.model_dump() if hasattr(plugin, "model_dump") else plugin.dict()
                for plugin in request.pluginManifests
            ]
            processed_params["pluginManifests"] = json.dumps(plugin_dicts)

        # Create query string
        query_string = urlencode([(k, v) for k, v in processed_params.items()])

        # Generate checksum
        checksum = generate_checksum("join", query_string, self.secret)

        # Create full URL
        join_url = f"{self.server_base_url}join?{query_string}&checksum={checksum}"

        # Either redirect or return the URL
        if request.redirect:
            return RedirectResponse(url=join_url)
        else:
            return {"join_url": join_url}

    async def end_meeting(
        self, request: EndMeetingRequest, db: AsyncSession
    ) -> Dict[str, Any]:
        """End a BBB meeting and update database."""
        params = {"meetingID": request.meeting_id, "password": request.password}

        # Call BBB API to end the meeting
        response = self._call_bbb_api("end", params)

        if response.get("returncode") == "SUCCESS":
            # Disconnect from Twitch if connected
            if self.twitch_client:
                await self.twitch_client.disconnect_from_meeting()
                self.twitch_client = None
                logger.info(f"[BBB] Meeting {request.meeting_id} ended, Twitch disconnected")

            # Update the meeting in the database
            stmt = select(BbbMeeting).where(BbbMeeting.meeting_id == request.meeting_id)
            result = await db.execute(stmt)
            meeting = result.scalars().first()

            if meeting:
                setattr(meeting, "has_been_forcibly_ended", "true")
                await db.commit()
                logger.info(f"Meeting ended and database updated: {request.meeting_id}")

        return response

    def is_meeting_running(self, request: IsMeetingRunningRequest) -> Dict[str, Any]:
        """Check if a meeting is running."""
        params = {"meetingID": request.meeting_id}

        return self._call_bbb_api("isMeetingRunning", params)

    def get_meeting_info(self, request: GetMeetingInfoRequest) -> Dict[str, Any]:
        """Get detailed information about a meeting."""
        if request.password:
            params = {"meetingID": request.meeting_id, "password": request.password}
        else:
            params = {"meetingID": request.meeting_id}

        return self._call_bbb_api("getMeetingInfo", params)

    def get_meetings(self) -> Dict[str, Any]:
        """Get the list of all meetings."""
        return self._call_bbb_api("getMeetings", {})

    def get_recordings(self, request: GetRecordingRequest) -> Dict[str, Any]:
        """Get the list of all recordings."""
        params = {
            "meetingID": request.meeting_id,
        }

        return self._call_bbb_api("getRecordings", params)

    def get_join_url(
        self,
        request: JoinMeetingRequest,
    ) -> str:
        """Generate a join URL for a BBB meeting."""
        # Create base params
        processed_params = {}

        # Process parameters
        for key, value in {
            "meetingID": request.meeting_id,
            "fullName": request.full_name,
            "password": request.password,
            "userID": request.user_id,
        }.items():
            if value is not None:
                processed_params[key] = value

        # Handle pluginManifests separately
        if request.pluginManifests:
            # Convert Pydantic models to dict first, then to JSON string
            plugin_dicts = [
                (
                    plugin.model_dump()
                    if hasattr(plugin, "model_dump")
                    else plugin.model_dump()
                )
                for plugin in request.pluginManifests
            ]
            processed_params["pluginManifests"] = json.dumps(plugin_dicts)

        query_string = urlencode([(k, v) for k, v in processed_params.items()])
        checksum = generate_checksum("join", query_string, self.secret)

        return f"{self.server_base_url}join?{query_string}&checksum={checksum}"

    def get_is_meeting_running_url(self, meeting_id: str) -> str:
        """Generate a URL to check if a meeting is running."""
        checksum = generate_checksum(
            "isMeetingRunning", f"meetingID={meeting_id}", self.secret
        )
        return f"{self.server_base_url}isMeetingRunning?meetingID={meeting_id}&checksum={checksum}"

    # Service for the plugin to get meeting id and mod password
    async def get_meeting_by_internal_id(
        self,
        internal_meeting_id: str,
        db: AsyncSession,
    ) -> Optional[BbbMeeting]:
        """Get the meeting details by internal meeting ID."""
        try:
            stmt = select(BbbMeeting).where(
                BbbMeeting.internal_meeting_id == internal_meeting_id
            )
            result = await db.execute(stmt)
            meeting = result.scalars().first()

            if not meeting:
                logger.warning(f"Meeting not found: {internal_meeting_id}")
                return None

            return meeting

        except Exception as e:
            logger.error(f"Error fetching meeting by internal ID: {e}")
            return None

    async def update_meeting_status(
        self,
        meeting_id: str,
        db: AsyncSession,
        is_ended: bool = False,
    ) -> Dict[str, Any]:
        """Update meeting details in the database."""
        try:
            # Find meeting in the database
            stmt = select(BbbMeeting).where(BbbMeeting.meeting_id == meeting_id)
            result = await db.execute(stmt)
            meeting = result.scalars().first()

            if not meeting:
                logger.warning(f"Meeting not found in database: {meeting_id}")
                return {"success": False, "error": "Meeting not found in database"}

            # If we know the meeting has ended (from callback), update directly
            if is_ended:
                setattr(meeting, "has_been_forcibly_ended", "true")
                await db.commit()
                logger.info(f"Meeting marked as ended via callback: {meeting_id}")
                return {"success": True}

            # Try to get info from BBB API
            try:
                meeting_info_request = GetMeetingInfoRequest(
                    meeting_id=meeting_id, password=""
                )
                meeting_info = self.get_meeting_info(request=meeting_info_request)

                # Update meeting status fields
                meeting.has_user_joined = meeting_info.get(
                    "hasUserJoined", meeting.has_user_joined
                )
                meeting.has_been_forcibly_ended = meeting_info.get(
                    "hasBeenForciblyEnded", meeting.has_been_forcibly_ended
                )
                await db.commit()
                logger.info(
                    f"Meeting updated with fresh info from BBB API: {meeting_id}"
                )
                return {"success": True}

            except HTTPException as e:
                # Handle case when meeting doesn't exist in BBB anymore
                if "notFound" in str(e.detail):
                    # Meeting has likely ended
                    setattr(meeting, "has_been_forcibly_ended", "true")
                    await db.commit()
                    logger.info(
                        f"Meeting not found in BBB, marked as ended: {meeting_id}"
                    )
                    return {
                        "success": True,
                        "message": "Meeting marked as ended (not found in BBB)",
                    }
                else:
                    # Some other API error
                    logger.error(f"BBB API error: {e}")
                    return {"success": False, "error": f"BBB API error: {str(e)}"}

        except Exception as e:
            logger.error(f"Error updating meeting status: {e}")
            return {"success": False, "error": str(e)}

    async def meeting_ended_callback(
        self,
        meeting_id: str,
        db: AsyncSession,
        event_id: Optional[UUID] = None,
    ) -> Dict[str, Any]:
        """Callback endpoint for when a BBB meeting ends."""
        try:
            # Use the update_meeting_status method with is_ended=True flag
            result = await self.update_meeting_status(
                meeting_id=meeting_id, db=db, is_ended=True
            )

            if result.get("success"):
                logger.info(
                    f"Meeting ended callback processed successfully: {meeting_id}"
                )
                # If event_id is provided, call the event service directly
                if event_id:
                    try:
                        # Get the user_id from the event
                        stmt = select(Event).where(Event.meeting_id == meeting_id)
                        event_result = await db.execute(stmt)
                        event = event_result.scalars().first()
                        if event and event.creator_id:
                            # Import the event service
                            from app.services.event_service import EventService

                            event_service = EventService()
                            await event_service.end_event(
                                event_id=event_id, db=db, user_id=event.creator_id
                            )
                            logger.info(
                                f"Event ended successfully via direct service call: {event_id}"
                            )
                        else:
                            logger.warning(
                                f"Event not found or creator_id missing for meeting: {meeting_id}"
                            )
                    except Exception as e:
                        logger.error(f"Error ending event via direct service call: {e}")

                return {"success": True, "message": "Meeting marked as ended"}
            else:
                logger.warning(
                    f"Failed to process meeting end callback: {result.get('error')}"
                )
                return result

        except Exception as e:
            logger.error(f"Error processing meeting end callback: {e}")
            return {"success": False, "error": str(e)}

    def _call_bbb_api(self, api_call: str, params: dict) -> dict:
        """Makes a call to the BBB API and returns the parsed XML response."""
        # Create a copy to avoid modifying the original
        processed_params = {}

        # Process parameters to handle special cases like pluginManifests
        for key, value in params.items():
            if key == "pluginManifests" and value:
                # Convert Pydantic models to dict first, then to JSON string
                if isinstance(value, list):
                    plugin_dicts = [
                        (
                            plugin.model_dump()
                            if hasattr(plugin, "model_dump")
                            else plugin.dict()
                        )
                        for plugin in value
                    ]
                    processed_params[key] = json.dumps(plugin_dicts)
            else:
                # For regular parameters, use them as is
                processed_params[key] = value

        # Sort parameters alphabetically as BBB requires
        query_string = urlencode(
            [(k, v) for k, v in processed_params.items() if v is not None]
        )

        # Generate checksum
        checksum = generate_checksum(api_call, query_string, self.secret)

        # Append checksum to parameters
        full_url = (
            f"{self.server_base_url}{api_call}?{query_string}&checksum={checksum}"
        )
        logger.debug(f"BBB API URL: {full_url}")

        # Make the API call
        response = requests.get(full_url)
        if response.status_code != 200:
            raise HTTPException(
                status_code=response.status_code, detail="BBB API request failed"
            )

        # Parse XML response
        return parse_xml_response(response.content, api_call)

    async def _clean_up_meetings(
        self,
        db: AsyncSession,
        days: int = 30,
    ):
        """Clean up meetings that have ended."""
        try:
            cutoff_date = datetime.now() - timedelta(days=days)

            stmt = select(BbbMeeting).where(BbbMeeting.created_at < cutoff_date)
            result = await db.execute(stmt)
            meetings = result.scalars().all()

            count = 0
            for meeting in meetings:
                # Delete the meeting from the database
                await db.delete(meeting)
                count += 1

            await db.commit()
            logger.info(f"Cleaned up {count} old meetings from the database.")

            return {"success": True, "message": f"Cleaned up {count} old meetings."}
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
            return {"success": False, "error": str(e)}

    async def _clean_up_meetings_background(self, days: int = 30):
        """Background task with its own DB session."""
        from app.config.database.session import engine

        async with AsyncSession(engine) as db:
            await self._clean_up_meetings(days=days, db=db)
            await db.commit()
