# The redlure Distributed Phishing Framework
redlure is a phishing framework designed to advance pentest and red team phishing. It could also be utilized by blue teams looking to train employees through running realistic phishing scenarios. 

redlure's distributed architecture allows for multiple campaigns to be run on different ports and/or servers, while results are aggregated in a single interface. This allows you to generate phishing templates, target lists, start/stop campaigns, change domains, change ports and generate Let's Encrypt certs on multiple workers all from one interface. 

redlure was released as a part of DEFCON 28 Demo Labs. ([Associated presentation/demo](https://www.youtube.com/watch?v=ZtCMnKHZJUM))
## redlure-console
This is the main redlure repository. Use the GitBook documentation on [docs.redlure.io](https://docs.redlure.io) to get started with the redlure-console or visit [Installation](https://docs.redlure.io/redlure-console/Installation.html) for install instructions.

## Sponsors
<a href="https://schneiderdowns.com">
    <img src="assets/sd-logo.jpg" height="170px">
</a>

## Core features
* Manage phishing campaigns running in parallel across multiple servers, ports and domains
* Chain webpage templates together for multi-step phishing (e.g. Office365, Gmail)
* Workspaces to manage results and templates for each engagement
* Partial database encryption (sensitive database columns only)
* Generate Let's Encrypt certs remotely (other certificates can be manually specified)
* Manage payload delivery via automatic downloads or links and buttons
* Role-based authentication

## redlure Ecosystem
redlure is comprised of three components:
1. redlure-console - Centralized API the operator interacts with. Stores templates and tracks campaigns/results. Manages your redlure-workers. Written in Python using Flask.
2. [redlure-worker](https://github.com/redlure/redlure-worker) - Skeletal API that manages the webserver for phishing campaigns. Multiple of these can and should be managed from a single console. Written in Python using Flask.
3. [redlure-client](https://github.com/redlure/redlure-client) - Web interface for interacting with the console API. Written with the Angular 10 framework (Typescript and HTML)

**Basic setup:**
<p align="center">
    <img src="assets/diagram-v2.PNG" height="500px">
</p>

## Project State
redlure is in an BETA state. It has been engagement-usable for my teams since early 2020. However, there are 100% still bugs that you may discover while using it. Please submit an issue or a pull request if you identify one.


## Disclaimer
This tool is designed for use during offensive security engagements, with explicit approval from client; usage of this tool without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse of this program.



