"""
DLS1 Server (Download Server)

Handles DLC/Event distribution for Nintendo DS/Wii games.
Port: 9003

Integrates with Django API to fetch Mystery Gifts.
"""

import asyncio
import base64
import logging
import random
import aiohttp
from aiohttp import web
from datetime import datetime
from typing import Optional, List, Dict

logger = logging.getLogger(__name__)

# Game families - games that share the same Mystery Gift pool across ALL regions
# All Diamond/Pearl games (any region) share gifts, all Platinum (any region) share gifts, etc.
GAME_FAMILIES = {
    # Pokemon Gen 4 - Diamond/Pearl (all regions)
    'diamond_pearl': ['ADAD', 'ADAE', 'ADAF', 'ADAI', 'ADAJ', 'ADAK', 'ADAS',  # Diamond
                      'APAD', 'APAE', 'APAF', 'APAI', 'APAJ', 'APAK', 'ADAS'],  # Pearl

    # Pokemon Gen 4 - Platinum (all regions)
    'platinum': ['CPUD', 'CPUE', 'CPUF', 'CPUI', 'CPUJ', 'CPUK', 'CPUS'],

    # Pokemon Gen 4 - HeartGold/SoulSilver (all regions)
    'heartgold_soulsilver': ['IPGD', 'IPGE', 'IPGF', 'IPGI', 'IPGJ', 'IPGK', 'IPGS'],

    # Pokemon Gen 5 - Black/White (all regions)
    'black_white': ['IRAO', 'IRBO', 'IRBD', 'IRBF', 'IRBI', 'IRBJ', 'IRBS'],
}

# Reverse mapping: game_id -> family name
GAME_TO_FAMILY = {}
for family, game_ids in GAME_FAMILIES.items():
    for game_id in game_ids:
        GAME_TO_FAMILY[game_id] = family


class DLS1Server:
    """DLC/Download Server implementation"""

    def __init__(self, config):
        self.config = config
        self.app = web.Application()
        self.runner = None
        self._setup_routes()

        # Django API settings
        self.api_base_url = getattr(config, 'API_BASE_URL', 'http://admin:7999/api')
        self.api_token = getattr(config, 'NAS_API_TOKEN', '')

        logger.info("DLS1 Server initialized")
        logger.info(f"Django API: {self.api_base_url}")

    def _get_family_game_ids(self, game_id: str) -> List[str]:
        """Get all game IDs in the same family.

        Example: APAD (Pearl DE) -> ['ADAD', 'ADAE', ..., 'APAD', 'APAE', ...]
        Returns: List of all game IDs in the family, or [game_id] if not in a family
        """
        family = GAME_TO_FAMILY.get(game_id)
        if family:
            game_ids = GAME_FAMILIES[family]
            logger.debug(f"[DLS1] Game {game_id} is in family '{family}' with {len(game_ids)} game IDs")
            return game_ids
        return [game_id]
    
    def _setup_routes(self):
        """Setup HTTP routes"""
        self.app.router.add_post('/download', self.handle_download)
        self.app.router.add_get('/health', self.handle_health)
        self.app.router.add_get('/', self.handle_root)

    def _decode_param(self, param: str) -> str:
        """
        Decode Nintendo's Base64-encoded parameters.

        Nintendo uses Base64 with '*' replacing '=' for padding.

        Args:
            param: Encoded parameter value

        Returns:
            Decoded string value
        """
        if not param:
            return ''

        try:
            # Replace '*' with '=' for standard Base64
            param_fixed = param.replace('*', '=')
            # Decode from Base64
            decoded_bytes = base64.b64decode(param_fixed)
            return decoded_bytes.decode('utf-8', errors='ignore')
        except Exception as e:
            logger.warning(f"[DLS1] Failed to decode param '{param}': {e}")
            return param

    async def handle_download(self, request: web.Request) -> web.Response:
        """Handle download requests (DLC, events, etc.)"""

        try:
            data = await request.post()
            data_dict = dict(data)

            # Decode Base64-encoded parameters (Nintendo format)
            action = self._decode_param(data_dict.get('action', '')).lower()
            gamecd = self._decode_param(data_dict.get('gamecd', ''))
            contents = self._decode_param(data_dict.get('contents', ''))
            userid = self._decode_param(data_dict.get('userid', ''))  # User ID from NAS login

            # Add decoded values back to data_dict for tracking
            data_dict['action'] = action
            data_dict['gamecd'] = gamecd
            data_dict['contents'] = contents
            data_dict['userid'] = userid
            data_dict['ip'] = request.remote
            data_dict['user_agent'] = request.headers.get('User-Agent', 'Unknown')

            logger.info(f"[DLS1] Download request: action={action}, game={gamecd}, user={userid}, ip={request.remote}")
            
            if action == 'count':
                return await self._handle_count(data_dict)
            elif action == 'list':
                return await self._handle_list(data_dict)
            elif action == 'contents':
                return await self._handle_contents(data_dict)
            else:
                logger.warning(f"[DLS1] Unknown action: {action}")
                return web.Response(status=404)
        
        except Exception as e:
            logger.error(f"[DLS1] Error: {e}", exc_info=True)
            return web.Response(status=500)
    
    async def _fetch_mystery_gifts(self, game_id: str) -> list:
        """Fetch available mystery gifts from Django API.

        If game_id is part of a family, fetches gifts from ALL game IDs in the family.
        """
        try:
            # Get all game IDs in the same family
            family_game_ids = self._get_family_game_ids(game_id)

            all_gifts = []
            headers = {}
            if self.api_token:
                headers['Authorization'] = f'Token {self.api_token}'

            async with aiohttp.ClientSession() as session:
                # Fetch gifts from each game ID in the family
                for gid in family_game_ids:
                    url = f"{self.api_base_url}/mystery-gifts/game/{gid}/"
                    logger.debug(f"[DLS1] Fetching gifts from: {url}")

                    async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as response:
                        if response.status == 200:
                            gifts = await response.json()
                            if gifts:
                                all_gifts.extend(gifts)
                                logger.debug(f"[DLS1] Fetched {len(gifts)} gifts from {gid}")

            # Remove duplicates by filename
            seen = set()
            unique_gifts = []
            for gift in all_gifts:
                if gift['filename'] not in seen:
                    seen.add(gift['filename'])
                    unique_gifts.append(gift)

            logger.info(f"[DLS1] Fetched {len(unique_gifts)} unique gifts for {game_id} (from {len(family_game_ids)} game IDs)")
            return unique_gifts

        except Exception as e:
            logger.error(f"[DLS1] Error fetching gifts: {e}", exc_info=True)
            return []

    async def _get_distribution_settings(self, game_id: str) -> Dict:
        """Get distribution settings for a game"""
        try:
            # Use first game ID from family for settings lookup
            family_game_ids = self._get_family_game_ids(game_id)
            settings_game_id = family_game_ids[0]

            url = f"{self.api_base_url}/game-distribution-settings/{settings_game_id}/"
            headers = {}
            if self.api_token:
                headers['Authorization'] = f'Token {self.api_token}'

            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as response:
                    if response.status == 200:
                        settings = await response.json()
                        logger.debug(f"[DLS1] Distribution settings for {resolved_game_id}: {settings}")
                        return settings
                    else:
                        # Default settings if not configured
                        logger.debug(f"[DLS1] No settings for {game_id}, using defaults")
                        return {
                            'distribution_mode': 'random',
                            'track_downloads': True,
                            'reset_on_completion': True
                        }
        except Exception as e:
            logger.error(f"[DLS1] Error fetching settings: {e}")
            return {
                'distribution_mode': 'random',
                'track_downloads': True,
                'reset_on_completion': True
            }

    async def _get_downloaded_gift_ids(self, profile_id: int, game_id: str) -> List[int]:
        """Get list of gift IDs already downloaded by this user"""
        try:
            url = f"{self.api_base_url}/mystery-gift-downloads/"
            params = {'profile': profile_id, 'game_id': game_id}
            headers = {}
            if self.api_token:
                headers['Authorization'] = f'Token {self.api_token}'

            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as response:
                    if response.status == 200:
                        downloads = await response.json()
                        gift_ids = [d['mystery_gift'] for d in downloads]
                        logger.debug(f"[DLS1] User {profile_id} has {len(gift_ids)} downloads for {game_id}")
                        return gift_ids
                    return []
        except Exception as e:
            logger.error(f"[DLS1] Error fetching downloads: {e}")
            return []

    async def _select_gift_for_user(self, all_gifts: List[Dict], game_id: str, profile_id: Optional[int], settings: Dict) -> Optional[Dict]:
        """Select one gift for the user based on distribution settings"""

        if not all_gifts:
            return None

        # If distribution mode is 'all', return all gifts (for non-Pokemon games)
        if settings['distribution_mode'] == 'all':
            return None  # Signal to return all gifts

        # Get already downloaded gifts if tracking is enabled
        available_gifts = all_gifts
        if settings['track_downloads'] and profile_id:
            downloaded_ids = await self._get_downloaded_gift_ids(profile_id, game_id)

            # Filter out already downloaded gifts
            available_gifts = [g for g in all_gifts if g['id'] not in downloaded_ids]

            # If user has all gifts and reset is enabled, start over
            if not available_gifts and settings['reset_on_completion']:
                logger.info(f"[DLS1] User {profile_id} completed all gifts for {game_id}, resetting")
                available_gifts = all_gifts

        if not available_gifts:
            logger.warning(f"[DLS1] No available gifts for user {profile_id} on {game_id}")
            return None

        # Select based on distribution mode
        if settings['distribution_mode'] == 'priority':
            # Pick highest priority gift
            selected = max(available_gifts, key=lambda g: (g.get('priority', 0), g['id']))
            logger.info(f"[DLS1] Selected gift by priority: {selected['filename']} (priority={selected.get('priority', 0)})")
        else:  # random
            selected = random.choice(available_gifts)
            logger.info(f"[DLS1] Selected random gift: {selected['filename']}")

        return selected

    async def _get_profile_id_from_user_id(self, user_id: str, game_id: str) -> Optional[int]:
        """Get profile_id from user_id and game_id"""
        try:
            url = f"{self.api_base_url}/profiles/"
            params = {'user_id': user_id, 'game_id': game_id}
            headers = {}
            if self.api_token:
                headers['Authorization'] = f'Token {self.api_token}'

            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as response:
                    if response.status == 200:
                        profiles = await response.json()
                        if profiles and len(profiles) > 0:
                            profile_id = profiles[0]['profile_id']
                            logger.debug(f"[DLS1] Found profile_id {profile_id} for user {user_id}")
                            return profile_id
            return None
        except Exception as e:
            logger.error(f"[DLS1] Error fetching profile: {e}")
            return None

    async def _handle_count(self, data: dict) -> web.Response:
        """Return count of available DLC - always returns 1 for tracked games, actual count for others"""
        game_id = data.get('gamecd', '')

        if not game_id:
            return web.Response(
                text='0',
                content_type='text/plain',
                headers={'X-DLS-Host': 'http://dls1.nintendowifi.net/'}
            )

        # Get distribution settings
        settings = await self._get_distribution_settings(game_id)

        # Fetch all gifts
        gifts = await self._fetch_mystery_gifts(game_id)

        if not gifts:
            logger.info(f"[DLS1] Count request for {game_id}: 0 gifts")
            return web.Response(
                text='0',
                content_type='text/plain',
                headers={'X-DLS-Host': 'http://dls1.nintendowifi.net/'}
            )

        # For 'all' mode, return actual count
        if settings['distribution_mode'] == 'all':
            count = len(gifts)
            logger.info(f"[DLS1] Count request for {game_id}: {count} gifts (all mode)")
            return web.Response(
                text=str(count),
                content_type='text/plain',
                headers={'X-DLS-Host': 'http://dls1.nintendowifi.net/'}
            )

        # For single-gift modes (random/priority), ALWAYS return 1
        # This matches Pokemon Gen 4 behavior
        logger.info(f"[DLS1] Count request for {game_id}: returning 1 (single-gift mode)")
        return web.Response(
            text='1',
            content_type='text/plain',
            headers={'X-DLS-Host': 'http://dls1.nintendowifi.net/'}
        )
    
    async def _handle_list(self, data: dict) -> web.Response:
        """Return list of available DLC - returns ONE gift for tracked games, all for others"""
        game_id = data.get('gamecd', '')
        user_id = data.get('userid', '')  # From NAS login

        logger.info(f"[DLS1] ========== LIST REQUEST RECEIVED ==========")
        logger.info(f"[DLS1] List request: game={game_id}, user={user_id}")

        if not game_id:
            logger.warning(f"[DLS1] List request missing game_id!")
            return web.Response(
                text='',
                content_type='text/plain',
                headers={'X-DLS-Host': 'http://dls1.nintendowifi.net/'}
            )

        # Get distribution settings
        settings = await self._get_distribution_settings(game_id)

        # Fetch all gifts
        gifts = await self._fetch_mystery_gifts(game_id)

        if not gifts:
            logger.warning(f"[DLS1] No gifts found for {game_id}")
            return web.Response(
                text='',
                content_type='text/plain',
                headers={'X-DLS-Host': 'http://dls1.nintendowifi.net/'}
            )

        # Get profile_id for tracking (if user_id is available)
        profile_id = None
        if user_id and settings['track_downloads']:
            profile_id = await self._get_profile_id_from_user_id(user_id, game_id)

        # Select gift(s) based on distribution mode
        selected_gift = await self._select_gift_for_user(gifts, game_id, profile_id, settings)

        # Build list response
        if selected_gift is None and settings['distribution_mode'] == 'all':
            # Return all gifts
            gifts_to_return = gifts
        elif selected_gift:
            # Return only the selected gift
            gifts_to_return = [selected_gift]
        else:
            # No gifts available for this user
            logger.warning(f"[DLS1] No available gifts for user {user_id} on {game_id}")
            return web.Response(
                text='',
                content_type='text/plain',
                headers={'X-DLS-Host': 'http://dls1.nintendowifi.net/'}
            )

        # Format: filename\t\t\t\t\tsize\n (5 tabs between filename and size, LF line ending)
        lines = []
        for gift in gifts_to_return:
            filename = gift.get('filename', '')
            file_size = gift.get('file_size', 0)
            if filename:
                lines.append(f"{filename}\t\t\t\t\t{file_size}")

        list_text = '\n'.join(lines)
        if list_text:
            list_text += '\r\n'  # Trailing CRLF (even though internal format uses LF)

        logger.info(f"[DLS1] List response for {game_id}: {len(gifts_to_return)} gift(s)")
        logger.info(f"[DLS1] List content: {repr(list_text)}")

        return web.Response(
            text=list_text,
            content_type='text/plain',
            headers={'X-DLS-Host': 'http://dls1.nintendowifi.net/'}
        )
    
    async def _handle_contents(self, data: dict) -> web.Response:
        """Return DLC content file"""
        game_id = data.get('gamecd', '')
        contents = data.get('contents', '')  # Filename requested

        if not game_id or not contents:
            logger.warning(f"[DLS1] Contents request missing game_id or filename")
            return web.Response(status=400)

        logger.info(f"[DLS1] Contents request: game={game_id}, file={contents}")

        try:
            # Get all game IDs in the same family
            family_game_ids = self._get_family_game_ids(game_id)

            # Fetch gift details from API - search across all family game IDs
            url = f"{self.api_base_url}/mystery-gifts/"
            headers = {}
            if self.api_token:
                headers['Authorization'] = f'Token {self.api_token}'

            gift = None
            async with aiohttp.ClientSession() as session:
                # Search each family game ID until we find the gift
                for gid in family_game_ids:
                    params = {'game_id': gid, 'filename': contents}
                    logger.debug(f"[DLS1] Searching for {contents} in game_id={gid}")

                    async with session.get(url, params=params, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as response:
                        if response.status == 200:
                            gifts_data = await response.json()

                            # Handle paginated response
                            gifts = gifts_data.get('results', gifts_data) if isinstance(gifts_data, dict) else gifts_data

                            if gifts and len(gifts) > 0:
                                gift = gifts[0]  # First match
                                logger.info(f"[DLS1] Found {contents} under game_id={gid}")
                                break

                if not gift:
                    logger.warning(f"[DLS1] No matching gift found in any family game ID")
                    return web.Response(status=404)

                file_url = gift.get('file_url')

                if not file_url:
                    logger.error(f"[DLS1] No file URL in gift data")
                    return web.Response(status=404)

                # Fix file URL for inter-container communication
                # Replace localhost with 'admin' service name
                file_url = file_url.replace('http://localhost:7999', 'http://admin:7999')
                file_url = file_url.replace('http://127.0.0.1:7999', 'http://admin:7999')

                logger.info(f"[DLS1] Fetching file from: {file_url}")

                # Download the actual file from Django
                async with session.get(file_url, timeout=aiohttp.ClientTimeout(total=30)) as file_response:
                    if file_response.status != 200:
                        logger.error(f"[DLS1] Failed to download file: {file_response.status}")
                        return web.Response(status=404)

                    file_data = await file_response.read()

                    logger.info(f"[DLS1] Serving {contents} ({len(file_data)} bytes)")

                    # Track download (async, don't wait)
                    asyncio.create_task(self._track_download(gift['id'], data))

                    return web.Response(
                        body=file_data,
                        content_type='application/x-dsdl',
                        headers={
                            'X-DLS-Host': 'http://dls1.nintendowifi.net/',
                            'Content-Disposition': f'attachment; filename="{contents}"'
                        }
                    )

        except Exception as e:
            logger.error(f"[DLS1] Error serving contents: {e}", exc_info=True)
            return web.Response(status=500)

    async def _track_download(self, gift_id: int, request_data: dict):
        """Track mystery gift download (async, fire-and-forget)"""
        try:
            url = f"{self.api_base_url}/mystery-gift-downloads/"
            headers = {'Content-Type': 'application/json'}
            if self.api_token:
                headers['Authorization'] = f'Token {self.api_token}'

            download_data = {
                'mystery_gift': gift_id,
                'ip_address': request_data.get('ip', '0.0.0.0'),
                'user_agent': request_data.get('user_agent', 'Nintendo DS/Wii')
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=download_data, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as response:
                    if response.status == 201:
                        logger.debug(f"[DLS1] Download tracked for gift #{gift_id}")
                    else:
                        logger.warning(f"[DLS1] Failed to track download: {response.status}")
        except Exception as e:
            logger.error(f"[DLS1] Error tracking download: {e}")
    
    async def handle_health(self, request: web.Request) -> web.Response:
        """Health check"""
        return web.json_response({
            'status': 'healthy',
            'service': 'DLS1',
            'timestamp': datetime.utcnow().isoformat()
        })
    
    async def handle_root(self, request: web.Request) -> web.Response:
        """Root endpoint"""
        return web.Response(
            text='Nintendo DLS1 Server\n',
            content_type='text/plain'
        )
    
    async def start(self):
        """Start DLS1 server"""
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        
        site = web.TCPSite(
            self.runner,
            self.config.DLS1_HOST,
            self.config.DLS1_PORT
        )
        await site.start()
        
        logger.info(
            f"🟢 DLS1 Server started on "
            f"{self.config.DLS1_HOST}:{self.config.DLS1_PORT}"
        )
    
    async def stop(self):
        """Stop DLS1 server"""
        if self.runner:
            await self.runner.cleanup()
            logger.info("DLS1 Server stopped")