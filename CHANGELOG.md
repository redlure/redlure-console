# Changelog
## [v0.12] - 3/26/2022
### Added
- Passphrase var in config.py. Will be required for use with Docker in a future update
### Changed
- Handling of console startup to accomodate option of hardcoded passphrase

## [v0.11] - 2/6/2022
### Added
- Begin changelog history
- Added versioning
- "Safety URL" feature - allow specification of a URL that vistors without a valid phish page URI will be redirected to
    - Required DB schema update
### Changed
- Updated `lxml` dependency 
- Fixed role name in logging for newly created users
