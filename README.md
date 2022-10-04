[comment]: # "Auto-generated SOAR connector documentation"
# VMRay

Publisher:  VMRay  
Connector Version: 2\.3\.0  
Product Vendor: VMRay GmbH  
Product Name: VMRay Platform  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.3\.4  

This app enables you to detonate files and URLs, and perform investigative actions, using the VMRay Platform, thereby giving you automated analysis and advanced threat detection through an agentless hypervisor\-based sandbox


## Port Information

The app uses HTTP/HTTPS protocol for communicating with the VMRay Server. Below are the default
ports used by Splunk SOAR.

| Service Name | Transport Protocol | Port |
|--------------|--------------------|------|
| http         | tcp                | 80   |
| https        | tcp                | 443  |


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a VMRay Platform asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**vmray\_server** |  required  | string | Server IP/Hostname
**vmray\_api\_key** |  required  | password | API Key
**disable\_cert\_verification** |  optional  | boolean | Disable Certificate Verification

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity  
[get file](#action-get-file) - Download a file from the VMRay Platform and add it to the vault  
[detonate file](#action-detonate-file) - Detonate file in the VMRay Platform  
[detonate url](#action-detonate-url) - Detonate a URL in the VMRay Platform  
[get report](#action-get-report) - Get the report\(s\) for a submission  
[get info](#action-get-info) - Get information of a specific sample  

## action: 'test connectivity'
Validate the asset configuration for connectivity

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'get file'
Download a file from the VMRay Platform and add it to the vault

Type: **investigate**  
Read only: **True**

Downloads the file with the given hash from the VMRay Platform and adds it to the vault\. This action returns a vault id which can be used to detonate the file\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | The hash of the file to be downloaded | string |  `hash`  `sha256`  `sha1`  `md5` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.hash | string |  `hash`  `md5`  `sha1`  `sha256` 
action\_result\.data\.\*\.vault\_id | string |  `vault id` 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary\.vault\_id | string |  `vault id` 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'detonate file'
Detonate file in the VMRay Platform

Type: **generic**  
Read only: **False**

The <b>file\_name</b> parameter overrides the filename, if none is given the app tries to get the filename from the vaults metadata\. The <b>type</b> overrides the automatic detection of the VMRay Platform\. The <b>config</b> parameter specifies additional configuration options passed to the VMRay Platform \(See user\_config in the REST API documentation\)\. With <b>jobrules</b> you can specify custom jobrule entries \(See jobrule\_enries in the REST API documentation\)\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault\_id** |  required  | The vault\_id of the file to be analyzed | string |  `vault id` 
**ioc\_only** |  optional  | Only import artifacts that are IOCs | boolean | 
**file\_name** |  optional  | The file name to use | string |  `file name` 
**comment** |  optional  | Comment for this submission | string | 
**tags** |  optional  | Tags for this submission | string | 
**type** |  optional  | The sample type | string | 
**config** |  optional  | Additional configuration | string | 
**jobrules** |  optional  | Jobrules | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.tags | string | 
action\_result\.parameter\.ioc\_only | boolean | 
action\_result\.parameter\.vault\_id | string |  `vault id` 
action\_result\.parameter\.type | string | 
action\_result\.parameter\.jobrules | string | 
action\_result\.parameter\.comment | string | 
action\_result\.parameter\.config | string | 
action\_result\.parameter\.file\_name | string |  `file name` 
action\_result\.data\.\*\.analysis\.analysis\_analyzer\_id | numeric | 
action\_result\.data\.\*\.analysis\.analysis\_analyzer\_name | string | 
action\_result\.data\.\*\.analysis\.analysis\_analyzer\_version | string | 
action\_result\.data\.\*\.analysis\.analysis\_configuration\_id | numeric | 
action\_result\.data\.\*\.analysis\.analysis\_configuration\_name | string | 
action\_result\.data\.\*\.analysis\.analysis\_created | string | 
action\_result\.data\.\*\.analysis\.analysis\_job\_id | numeric | 
action\_result\.data\.\*\.analysis\.analysis\_job\_started | string | 
action\_result\.data\.\*\.analysis\.analysis\_jobrule\_id | numeric | 
action\_result\.data\.\*\.analysis\.analysis\_jobrule\_sampletype | string | 
action\_result\.data\.\*\.analysis\.analysis\_prescript\_id | numeric | 
action\_result\.data\.\*\.analysis\.analysis\_priority | numeric | 
action\_result\.data\.\*\.analysis\.analysis\_result\_code | numeric | 
action\_result\.data\.\*\.analysis\.analysis\_result\_str | string | 
action\_result\.data\.\*\.analysis\.analysis\_sample\_id | numeric |  `vmray sample id` 
action\_result\.data\.\*\.analysis\.analysis\_sample\_md5 | string |  `md5` 
action\_result\.data\.\*\.analysis\.analysis\_sample\_sha1 | string |  `sha1` 
action\_result\.data\.\*\.analysis\.analysis\_sample\_sha256 | string |  `sha256` 
action\_result\.data\.\*\.analysis\.analysis\_verdict | string | 
action\_result\.data\.\*\.analysis\.analysis\_size | numeric | 
action\_result\.data\.\*\.analysis\.analysis\_snapshot\_id | numeric | 
action\_result\.data\.\*\.analysis\.analysis\_snapshot\_name | string | 
action\_result\.data\.\*\.analysis\.analysis\_submission\_id | numeric |  `vmray submission id` 
action\_result\.data\.\*\.analysis\.analysis\_user\_email | string | 
action\_result\.data\.\*\.analysis\.analysis\_user\_id | numeric | 
action\_result\.data\.\*\.analysis\.analysis\_vm\_id | numeric | 
action\_result\.data\.\*\.analysis\.analysis\_vm\_name | string | 
action\_result\.data\.\*\.analysis\.analysis\_vmhost\_id | numeric | 
action\_result\.data\.\*\.analysis\.analysis\_vmhost\_name | string | 
action\_result\.data\.\*\.analysis\.analysis\_vti\_built\_in\_rules\_version | string | 
action\_result\.data\.\*\.analysis\.analysis\_vti\_custom\_rules\_hash | string | 
action\_result\.data\.\*\.analysis\.analysis\_vti\_score | numeric | 
action\_result\.data\.\*\.analysis\.analysis\_webif\_url | string | 
action\_result\.data\.\*\.analysis\.analysis\_yara\_latest\_ruleset\_date | string | 
action\_result\.data\.\*\.analysis\.analysis\_yara\_match\_count | numeric | 
action\_result\.data\.\*\.reputation\_lookup\.reputation\_lookup\_created | string | 
action\_result\.data\.\*\.reputation\_lookup\.reputation\_lookup\_id | numeric | 
action\_result\.data\.\*\.reputation\_lookup\.reputation\_lookup\_job\_id | numeric | 
action\_result\.data\.\*\.reputation\_lookup\.reputation\_lookup\_result\_code | numeric | 
action\_result\.data\.\*\.reputation\_lookup\.reputation\_lookup\_sample\_id | numeric |  `vmray sample id` 
action\_result\.data\.\*\.reputation\_lookup\.reputation\_lookup\_sample\_md5 | string |  `md5` 
action\_result\.data\.\*\.reputation\_lookup\.reputation\_lookup\_sample\_sha1 | string |  `sha1` 
action\_result\.data\.\*\.reputation\_lookup\.reputation\_lookup\_sample\_sha256 | string |  `sha256` 
action\_result\.data\.\*\.reputation\_lookup\.reputation\_lookup\_verdict | string | 
action\_result\.data\.\*\.reputation\_lookup\.reputation\_lookup\_submission\_id | numeric | 
action\_result\.data\.\*\.reputation\_lookup\.reputation\_lookup\_user\_email | string | 
action\_result\.data\.\*\.reputation\_lookup\.reputation\_lookup\_user\_id | numeric | 
action\_result\.data\.\*\.analysis\.summary\.extracted\_files\.\*\.md5\_hash | string |  `md5` 
action\_result\.data\.\*\.analysis\.summary\.extracted\_files\.\*\.sha1\_hash | string |  `sha1` 
action\_result\.data\.\*\.analysis\.summary\.extracted\_files\.\*\.sha256\_hash | string |  `sha256` 
action\_result\.data\.\*\.analysis\.summary\.extracted\_files\.\*\.norm\_filename | string |  `file path` 
action\_result\.data\.\*\.analysis\.summary\.artifacts\.ips\.\*\.ip\_address | string |  `ip` 
action\_result\.data\.\*\.analysis\.summary\.artifacts\.urls\.\*\.url | string |  `url` 
action\_result\.data\.\*\.analysis\.summary\.artifacts\.mutexes\.\*\.mutex\_name | string | 
action\_result\.data\.\*\.analysis\.summary\.artifacts\.registry\.\*\.reg\_key\_name | string | 
action\_result\.data\.\*\.analysis\.summary\.artifacts\.files\.\*\.norm\_filename | string |  `file path` 
action\_result\.data\.\*\.analysis\.summary\.artifacts\.domains\.\*\.domain | string |  `domain` 
action\_result\.data\.\*\.analysis\.summary\.artifacts\.emails\.\*\.sender | string |  `email` 
action\_result\.data\.\*\.analysis\.summary\.artifacts\.emails\.\*\.subject | string | 
action\_result\.data\.\*\.analysis\.summary\.artifacts\.processes\.\*\.cmd\_line | string | 
action\_result\.data\.\*\.analysis\.summary\.mitre\_attack\.techniques\.\*\.description | string | 
action\_result\.data\.\*\.analysis\.summary\.mitre\_attack\.techniques\.\*\.id | string | 
action\_result\.data\.\*\.analysis\.summary\.vti\.vti\_rule\_matches\.\*\.category\_desc | string | 
action\_result\.data\.\*\.analysis\.summary\.vti\.vti\_rule\_matches\.\*\.rule\_score | numeric | 
action\_result\.data\.\*\.analysis\.summary\.vti\.vti\_rule\_matches\.\*\.operation\_desc | string | 
action\_result\.data\.\*\.analysis\.summary\.vti\.vti\_rule\_matches\.\*\.rule\_classifications | string | 
action\_result\.data\.\*\.analysis\.summary\.vti\.vti\_rule\_matches\.\*\.technique\_desc | string | 
action\_result\.data\.\*\.analysis\.summary\.vti\.vti\_rule\_matches\.\*\.threat\_names\.\*\.name | string | 
action\_result\.data\.\*\.analysis\.analysis\_id | numeric |  `vmray analysis id` 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary\.submission\_id | numeric |  `vmray submission id` 
action\_result\.summary\.submission\_finished | boolean | 
action\_result\.summary\.verdict | string | 
action\_result\.summary\.url | string | 
action\_result\.summary\.billing\_type | string | 
action\_result\.summary\.recursive\_submission\_ids\.child\_submission\_ids\.\*\.child\_submission\_id | numeric |  `vmray submission id` 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'detonate url'
Detonate a URL in the VMRay Platform

Type: **generic**  
Read only: **False**

See <b>detonate file</b> for a detailed parameter description\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL to detonate | string |  `url` 
**ioc\_only** |  optional  | Only import artifacts that are IOCs | boolean | 
**comment** |  optional  | Comment for this submission | string | 
**tags** |  optional  | Tags added for this submission | string | 
**config** |  optional  | Additional configuration | string | 
**jobrules** |  optional  | Jobrules | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.tags | string | 
action\_result\.parameter\.jobrules | string | 
action\_result\.parameter\.comment | string | 
action\_result\.parameter\.config | string | 
action\_result\.parameter\.url | string |  `url` 
action\_result\.parameter\.ioc\_only | boolean | 
action\_result\.data\.\*\.analysis\.analysis\_analyzer\_id | numeric | 
action\_result\.data\.\*\.analysis\.analysis\_analyzer\_name | string | 
action\_result\.data\.\*\.analysis\.analysis\_analyzer\_version | string | 
action\_result\.data\.\*\.analysis\.analysis\_configuration\_id | numeric | 
action\_result\.data\.\*\.analysis\.analysis\_configuration\_name | string | 
action\_result\.data\.\*\.analysis\.analysis\_created | string | 
action\_result\.data\.\*\.analysis\.analysis\_id | numeric |  `vmray analysis id` 
action\_result\.data\.\*\.analysis\.analysis\_job\_id | numeric | 
action\_result\.data\.\*\.analysis\.analysis\_job\_started | string | 
action\_result\.data\.\*\.analysis\.analysis\_jobrule\_id | numeric | 
action\_result\.data\.\*\.analysis\.analysis\_jobrule\_sampletype | string | 
action\_result\.data\.\*\.analysis\.analysis\_prescript\_id | numeric | 
action\_result\.data\.\*\.analysis\.analysis\_priority | numeric | 
action\_result\.data\.\*\.analysis\.analysis\_result\_code | numeric | 
action\_result\.data\.\*\.analysis\.analysis\_result\_str | string | 
action\_result\.data\.\*\.analysis\.analysis\_sample\_id | numeric |  `vmray sample id` 
action\_result\.data\.\*\.analysis\.analysis\_sample\_md5 | string |  `md5` 
action\_result\.data\.\*\.analysis\.analysis\_sample\_sha1 | string |  `sha1` 
action\_result\.data\.\*\.analysis\.analysis\_sample\_sha256 | string |  `sha256` 
action\_result\.data\.\*\.analysis\.analysis\_verdict | string | 
action\_result\.data\.\*\.analysis\.analysis\_size | numeric | 
action\_result\.data\.\*\.analysis\.analysis\_snapshot\_id | numeric | 
action\_result\.data\.\*\.analysis\.analysis\_snapshot\_name | string | 
action\_result\.data\.\*\.analysis\.analysis\_submission\_id | numeric |  `vmray submission id` 
action\_result\.data\.\*\.analysis\.analysis\_user\_email | string | 
action\_result\.data\.\*\.analysis\.analysis\_user\_id | numeric | 
action\_result\.data\.\*\.analysis\.analysis\_vm\_id | numeric | 
action\_result\.data\.\*\.analysis\.analysis\_vm\_name | string | 
action\_result\.data\.\*\.analysis\.analysis\_vmhost\_id | numeric | 
action\_result\.data\.\*\.analysis\.analysis\_vmhost\_name | string | 
action\_result\.data\.\*\.analysis\.analysis\_vti\_built\_in\_rules\_version | string | 
action\_result\.data\.\*\.analysis\.analysis\_vti\_custom\_rules\_hash | string | 
action\_result\.data\.\*\.analysis\.analysis\_vti\_score | numeric | 
action\_result\.data\.\*\.analysis\.analysis\_webif\_url | string | 
action\_result\.data\.\*\.analysis\.analysis\_yara\_latest\_ruleset\_date | string | 
action\_result\.data\.\*\.analysis\.analysis\_yara\_match\_count | numeric | 
action\_result\.data\.\*\.reputation\_lookup\.reputation\_lookup\_created | string | 
action\_result\.data\.\*\.reputation\_lookup\.reputation\_lookup\_id | numeric | 
action\_result\.data\.\*\.reputation\_lookup\.reputation\_lookup\_job\_id | numeric | 
action\_result\.data\.\*\.reputation\_lookup\.reputation\_lookup\_result\_code | numeric | 
action\_result\.data\.\*\.reputation\_lookup\.reputation\_lookup\_sample\_id | numeric |  `vmray sample id` 
action\_result\.data\.\*\.reputation\_lookup\.reputation\_lookup\_sample\_md5 | string |  `md5` 
action\_result\.data\.\*\.reputation\_lookup\.reputation\_lookup\_sample\_sha1 | string |  `sha1` 
action\_result\.data\.\*\.reputation\_lookup\.reputation\_lookup\_sample\_sha256 | string |  `sha256` 
action\_result\.data\.\*\.reputation\_lookup\.reputation\_lookup\_verdict | string | 
action\_result\.data\.\*\.reputation\_lookup\.reputation\_lookup\_submission\_id | numeric | 
action\_result\.data\.\*\.reputation\_lookup\.reputation\_lookup\_user\_email | string | 
action\_result\.data\.\*\.reputation\_lookup\.reputation\_lookup\_user\_id | numeric | 
action\_result\.data\.\*\.analysis\.summary\.extracted\_files\.\*\.md5\_hash | string |  `md5` 
action\_result\.data\.\*\.analysis\.summary\.extracted\_files\.\*\.sha1\_hash | string |  `hash`  `sha1` 
action\_result\.data\.\*\.analysis\.summary\.extracted\_files\.\*\.sha256\_hash | string |  `hash`  `sha256` 
action\_result\.data\.\*\.analysis\.summary\.extracted\_files\.\*\.norm\_filename | string |  `file path` 
action\_result\.data\.\*\.analysis\.summary\.artifacts\.ips\.\*\.ip\_address | string |  `ip` 
action\_result\.data\.\*\.analysis\.summary\.artifacts\.urls\.\*\.url | string |  `url` 
action\_result\.data\.\*\.analysis\.summary\.artifacts\.mutexes\.\*\.mutex\_name | string | 
action\_result\.data\.\*\.analysis\.summary\.artifacts\.registry\.\*\.reg\_key\_name | string | 
action\_result\.data\.\*\.analysis\.summary\.artifacts\.files\.\*\.norm\_filename | string |  `file path` 
action\_result\.data\.\*\.analysis\.summary\.artifacts\.domains\.\*\.domain | string |  `domain` 
action\_result\.data\.\*\.analysis\.summary\.artifacts\.emails\.\*\.sender | string |  `email` 
action\_result\.data\.\*\.analysis\.summary\.artifacts\.emails\.\*\.subject | string | 
action\_result\.data\.\*\.analysis\.summary\.artifacts\.processes\.\*\.cmd\_line | string | 
action\_result\.data\.\*\.analysis\.summary\.mitre\_attack\.techniques\.\*\.description | string | 
action\_result\.data\.\*\.analysis\.summary\.mitre\_attack\.techniques\.\*\.id | string | 
action\_result\.data\.\*\.analysis\.summary\.vti\.vti\_rule\_matches\.\*\.category\_desc | string | 
action\_result\.data\.\*\.analysis\.summary\.vti\.vti\_rule\_matches\.\*\.rule\_score | numeric | 
action\_result\.data\.\*\.analysis\.summary\.vti\.vti\_rule\_matches\.\*\.operation\_desc | string | 
action\_result\.data\.\*\.analysis\.summary\.vti\.vti\_rule\_matches\.\*\.rule\_classifications | string | 
action\_result\.data\.\*\.analysis\.summary\.vti\.vti\_rule\_matches\.\*\.technique\_desc | string | 
action\_result\.data\.\*\.analysis\.summary\.vti\.vti\_rule\_matches\.\*\.threat\_names\.\*\.name | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary\.submission\_id | numeric |  `vmray submission id` 
action\_result\.summary\.submission\_finished | boolean | 
action\_result\.summary\.verdict | string | 
action\_result\.summary\.url | string | 
action\_result\.summary\.billing\_type | string | 
action\_result\.summary\.recursive\_submission\_ids\.child\_submission\_ids\.\*\.child\_submission\_id | numeric |  `vmray submission id` 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get report'
Get the report\(s\) for a submission

Type: **investigate**  
Read only: **True**

This action requires a <b>submission\_id</b>\. The <b>timeout</b> parameter specifies the time to wait for the report to be finished before aborting this action\. The <b>timeout</b> is specified in seconds\. Zero indicates no wait, hence the action will return immediately\. If this option is not set it will default to a five\-minute timeout\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**submission\_id** |  required  | The VMRay Platform submission ID | numeric |  `vmray submission id` 
**ioc\_only** |  optional  | Only import artifacts that are IOCs | boolean | 
**timeout** |  optional  | Timeout | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.submission\_id | numeric |  `vmray submission id` 
action\_result\.parameter\.ioc\_only | boolean | 
action\_result\.parameter\.timeout | numeric | 
action\_result\.data\.\*\.analysis\.analysis\_analyzer\_id | numeric | 
action\_result\.data\.\*\.analysis\.analysis\_analyzer\_name | string | 
action\_result\.data\.\*\.analysis\.analysis\_analyzer\_version | string | 
action\_result\.data\.\*\.analysis\.analysis\_configuration\_id | numeric | 
action\_result\.data\.\*\.analysis\.analysis\_configuration\_name | string | 
action\_result\.data\.\*\.analysis\.analysis\_created | string | 
action\_result\.data\.\*\.analysis\.analysis\_id | numeric |  `vmray analysis id` 
action\_result\.data\.\*\.analysis\.analysis\_job\_id | numeric | 
action\_result\.data\.\*\.analysis\.analysis\_job\_started | string | 
action\_result\.data\.\*\.analysis\.analysis\_jobrule\_id | numeric | 
action\_result\.data\.\*\.analysis\.analysis\_jobrule\_sampletype | string | 
action\_result\.data\.\*\.analysis\.analysis\_prescript\_id | numeric | 
action\_result\.data\.\*\.analysis\.analysis\_priority | numeric | 
action\_result\.data\.\*\.analysis\.analysis\_result\_code | numeric | 
action\_result\.data\.\*\.analysis\.analysis\_result\_str | string | 
action\_result\.data\.\*\.analysis\.analysis\_sample\_id | numeric |  `vmray sample id` 
action\_result\.data\.\*\.analysis\.analysis\_sample\_md5 | string |  `md5` 
action\_result\.data\.\*\.analysis\.analysis\_sample\_sha1 | string |  `sha1` 
action\_result\.data\.\*\.analysis\.analysis\_sample\_sha256 | string |  `sha256` 
action\_result\.data\.\*\.analysis\.analysis\_verdict | string | 
action\_result\.data\.\*\.analysis\.analysis\_size | numeric | 
action\_result\.data\.\*\.analysis\.analysis\_snapshot\_id | numeric | 
action\_result\.data\.\*\.analysis\.analysis\_snapshot\_name | string | 
action\_result\.data\.\*\.analysis\.analysis\_submission\_id | numeric |  `vmray submission id` 
action\_result\.data\.\*\.analysis\.analysis\_user\_email | string | 
action\_result\.data\.\*\.analysis\.analysis\_user\_id | numeric | 
action\_result\.data\.\*\.analysis\.analysis\_vm\_id | numeric | 
action\_result\.data\.\*\.analysis\.analysis\_vm\_name | string | 
action\_result\.data\.\*\.analysis\.analysis\_vmhost\_id | numeric | 
action\_result\.data\.\*\.analysis\.analysis\_vmhost\_name | string | 
action\_result\.data\.\*\.analysis\.analysis\_vti\_built\_in\_rules\_version | string | 
action\_result\.data\.\*\.analysis\.analysis\_vti\_custom\_rules\_hash | string | 
action\_result\.data\.\*\.analysis\.analysis\_vti\_score | numeric | 
action\_result\.data\.\*\.analysis\.analysis\_webif\_url | string | 
action\_result\.data\.\*\.analysis\.analysis\_yara\_latest\_ruleset\_date | string | 
action\_result\.data\.\*\.analysis\.analysis\_yara\_match\_count | numeric | 
action\_result\.data\.\*\.reputation\_lookup\.reputation\_lookup\_created | string | 
action\_result\.data\.\*\.reputation\_lookup\.reputation\_lookup\_id | numeric | 
action\_result\.data\.\*\.reputation\_lookup\.reputation\_lookup\_job\_id | numeric | 
action\_result\.data\.\*\.reputation\_lookup\.reputation\_lookup\_result\_code | numeric | 
action\_result\.data\.\*\.reputation\_lookup\.reputation\_lookup\_sample\_id | numeric |  `vmray sample id` 
action\_result\.data\.\*\.reputation\_lookup\.reputation\_lookup\_sample\_md5 | string |  `md5` 
action\_result\.data\.\*\.reputation\_lookup\.reputation\_lookup\_sample\_sha1 | string |  `sha1` 
action\_result\.data\.\*\.reputation\_lookup\.reputation\_lookup\_sample\_sha256 | string |  `sha256` 
action\_result\.data\.\*\.reputation\_lookup\.reputation\_lookup\_verdict | string | 
action\_result\.data\.\*\.reputation\_lookup\.reputation\_lookup\_submission\_id | numeric | 
action\_result\.data\.\*\.reputation\_lookup\.reputation\_lookup\_user\_email | string | 
action\_result\.data\.\*\.reputation\_lookup\.reputation\_lookup\_user\_id | numeric | 
action\_result\.data\.\*\.analysis\.summary\.extracted\_files\.\*\.md5\_hash | string |  `md5` 
action\_result\.data\.\*\.analysis\.summary\.extracted\_files\.\*\.sha1\_hash | string |  `sha1` 
action\_result\.data\.\*\.analysis\.summary\.extracted\_files\.\*\.sha256\_hash | string |  `sha256` 
action\_result\.data\.\*\.analysis\.summary\.extracted\_files\.\*\.norm\_filename | string |  `file path` 
action\_result\.data\.\*\.analysis\.summary\.artifacts\.ips\.\*\.ip\_address | string |  `ip` 
action\_result\.data\.\*\.analysis\.summary\.artifacts\.urls\.\*\.url | string |  `url` 
action\_result\.data\.\*\.analysis\.summary\.artifacts\.mutexes\.\*\.mutex\_name | string | 
action\_result\.data\.\*\.analysis\.summary\.artifacts\.registry\.\*\.reg\_key\_name | string | 
action\_result\.data\.\*\.analysis\.summary\.artifacts\.files\.\*\.norm\_filename | string |  `file path` 
action\_result\.data\.\*\.analysis\.summary\.artifacts\.domains\.\*\.domain | string |  `domain` 
action\_result\.data\.\*\.analysis\.summary\.artifacts\.emails\.\*\.sender | string |  `email` 
action\_result\.data\.\*\.analysis\.summary\.artifacts\.emails\.\*\.subject | string | 
action\_result\.data\.\*\.analysis\.summary\.artifacts\.processes\.\*\.cmd\_line | string | 
action\_result\.data\.\*\.analysis\.summary\.mitre\_attack\.techniques\.\*\.description | string | 
action\_result\.data\.\*\.analysis\.summary\.mitre\_attack\.techniques\.\*\.id | string | 
action\_result\.data\.\*\.analysis\.summary\.vti\.vti\_rule\_matches\.\*\.category\_desc | string | 
action\_result\.data\.\*\.analysis\.summary\.vti\.vti\_rule\_matches\.\*\.rule\_score | numeric | 
action\_result\.data\.\*\.analysis\.summary\.vti\.vti\_rule\_matches\.\*\.operation\_desc | string | 
action\_result\.data\.\*\.analysis\.summary\.vti\.vti\_rule\_matches\.\*\.rule\_classifications | string | 
action\_result\.data\.\*\.analysis\.summary\.vti\.vti\_rule\_matches\.\*\.technique\_desc | string | 
action\_result\.data\.\*\.analysis\.summary\.vti\.vti\_rule\_matches\.\*\.threat\_names\.\*\.name | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary\.submission\_id | numeric |  `vmray submission id` 
action\_result\.summary\.verdict | string | 
action\_result\.summary\.url | numeric | 
action\_result\.summary\.billing\_type | string | 
action\_result\.summary\.recursive\_submission\_ids\.child\_submission\_ids\.\*\.child\_submission\_id | numeric |  `vmray submission id` 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get info'
Get information of a specific sample

Type: **investigate**  
Read only: **True**

This action gets information about a sample given its <b>hash</b>\. See <b>get report</b> for a description of the <b>timeout</b> parameter\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | The sample hash | string |  `hash`  `sha256`  `sha1`  `md5` 
**timeout** |  optional  | Timeout | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.hash | string |  `hash`  `md5`  `sha1`  `sha256` 
action\_result\.parameter\.timeout | numeric | 
action\_result\.data\.\*\.sample\_type | string | 
action\_result\.data\.\*\.sample\_created | string | 
action\_result\.data\.\*\.sample\_filename | string |  `file name` 
action\_result\.data\.\*\.sample\_filesize | numeric | 
action\_result\.data\.\*\.sample\_highest\_vti\_score | numeric | 
action\_result\.data\.\*\.sample\_id | numeric |  `vmray sample id` 
action\_result\.data\.\*\.sample\_is\_multipart | boolean | 
action\_result\.data\.\*\.sample\_last\_md\_score | numeric | 
action\_result\.data\.\*\.sample\_last\_vt\_score | numeric | 
action\_result\.data\.\*\.sample\_md5hash | string |  `md5` 
action\_result\.data\.\*\.sample\_priority | numeric | 
action\_result\.data\.\*\.sample\_score | numeric | 
action\_result\.data\.\*\.sample\_verdict | string | 
action\_result\.data\.\*\.sample\_sha1hash | string |  `sha1` 
action\_result\.data\.\*\.sample\_sha256hash | string |  `sha256` 
action\_result\.data\.\*\.sample\_url | string |  `url` 
action\_result\.data\.\*\.sample\_vti\_score | numeric | 
action\_result\.data\.\*\.sample\_webif\_url | string | 
action\_result\.data\.\*\.sample\_classifications | string | 
action\_result\.data\.\*\.sample\_threat\_names | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary\.score | numeric | 
action\_result\.summary\.verdict | string | 
action\_result\.summary\.recursive\_sample\_ids\.parent\_sample\_ids\.\*\.parent\_sample\_id | numeric |  `vmray sample id` 
action\_result\.summary\.recursive\_sample\_ids\.child\_sample\_ids\.\*\.child\_sample\_id | numeric |  `vmray sample id` 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 