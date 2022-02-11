# TripFlare

**Slackbot for monitoring external malware databases for uploads of novel malware.**

Proper functionality requires at least:
 - Slack Bot and App token
 - At least one API token

<hr>
Example Yaml config

```
slack:
        bot_token: 
        app_token: 
api:
        virus_total: 
        vx:
			username:
			password:
        malware_bazaar: 
        hybrid_analysis:        
```
<hr>

App Manifest Yaml
```
_metadata:
  major_version: 1
  minor_version: 1
display_information:
  name: TripFlare
features:
  app_home:
    home_tab_enabled: false
    messages_tab_enabled: true
    messages_tab_read_only_enabled: true
  bot_user:
    display_name: TripFlare
    always_online: false
oauth_config:
  scopes:
    bot:
      - channels:history
      - chat:write
      - groups:history
      - im:history
      - mpim:history
      - users:read
settings:
  event_subscriptions:
    bot_events:
      - message.channels
      - message.groups
      - message.im
      - message.mpim
  interactivity:
    is_enabled: true
  org_deploy_enabled: false
  socket_mode_enabled: true
```
