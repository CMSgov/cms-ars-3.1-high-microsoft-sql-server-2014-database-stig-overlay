# cms-ars-3.1-high-microsoft-sql-server-2014-database-stig-overlay
**CMS’ ISPG (Information Security and Privacy Group) decided to discontinue funding the customization of MITRE’s Security Automation Framework (SAF) for CMS after September 2023. This repo is now in archive mode, but still accessible. For more information about SAF with current links, see https://security.cms.gov/learn/security-automation-framework-saf**


InSpec profile overlay to validate the secure configuration of Microsoft SQL Server 2014 Database against [DISA's](https://iase.disa.mil/stigs/Pages/index.aspx) Microsoft SQL Server 2014 Database STIG Version 1 Release 6 tailored for [CMS ARS 3.1](https://www.cms.gov/Research-Statistics-Data-and-Systems/CMS-Information-Technology/InformationSecurity/Info-Security-Library-Items/ARS-31-Publication.html) for CMS systems categorized as High.

## Getting Started  
It is intended and recommended that InSpec and this profile overlay be run from a __"runner"__ host (such as a DevOps orchestration server, an administrative management system, or a developer's workstation/laptop) against the target remotely over __winrm__.

__For the best security of the runner, always install on the runner the _latest version_ of InSpec and supporting Ruby language components.__ 

Latest versions and installation options are available at the [InSpec](http://inspec.io/) site.

## Tailoring to Your Environment
The following inputs must be configured in an inputs ".yml" file for the profile to run correctly for your specific environment. More information about InSpec inputs can be found in the [InSpec Profile Documentation](https://www.inspec.io/docs/reference/profiles/).

```
# Description: Username for MSSQL DB Server (e.g., null)
user: 

# Description: Password for MSSQL DB Server (e.g., null)
password: 

# Description: Hostname of MSSQL DB Server (e.g., null)
host: 

# Description: Instance name of MSSQL DB Server (e.g., null)
instance: 

# Description: Port number of MSSQL DB Server (e.g., 49789)
port: 

# Description: Name of the specific database being evaluated within the MSSQL DB Server (e.g., 'master')
db_name: ''

# Description: Set to true if SQL Server Trace or Server Audit is required for audit purposes
server_trace_or_audit_required: false

# Description: Set to true if SQL Server Trace is in use for audit purposes
server_trace_implemented: false

# Description: Set to true if SQL Server Audit is in use for audit purposes
server_audit_implemented: false

# Description: Specify if SQL Server Audit is not in use at the database level
server_audit_at_database_level_required: false

# Description: User with `ALTER ANY DATABASE AUDIT` or `CONTROL` permission
approved_audit_maintainers: []

# Description: Name of the timed job that automatically checks all system and user-defined procedures for being modified
track_stored_procedures_changes_job_name: ''

# Description: Name of the timed job that automatically checks all system and user-defined triggers for being modified
track_triggers_changes_job_name: ''

# Description: Name of the timed job that automatically checks all system and user-defined functions for being modified
track_functions_changes_job_name: ''

# Description: Identify SQL Server accounts authorized to own database objects
authorized_principals: []

# Description: Set to true if data at rest encryption is required
data_at_rest_encryption_required: false

# Description: Set to true if full disk encryption is in place
full_disk_encryption_inplace: false

# Description: Set to true if security labeling is required
security_labeling_required: false
```

## Running This Overlay Directly from Github

```
# How to run
inspec exec https://github.com/CMSgov/cms-ars-3.1-high-microsoft-sql-server-2014-database-stig-overlay/archive/master.tar.gz --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --target=winrm://<your_target_host_name_or_ip_address> --user=<target_account_with_administrative_privileges> --password=<password_for_target_account>--reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```

### Different Run Options

  [Full exec options](https://docs.chef.io/inspec/cli/#options-3)

## Running This Overlay from a local Archive copy 

If your runner is not always expected to have direct access to GitHub, use the following steps to create an archive bundle of this overlay and all of its dependent tests:

(Git is required to clone the InSpec profile using the instructions below. Git can be downloaded from the [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) site.)

When the __"runner"__ host uses this profile overlay for the first time, follow these steps: 

```
mkdir profiles
cd profiles
git clone https://github.com/CMSgov/cms-ars-3.1-high-microsoft-sql-server-2014-database-stig-overlay.git
inspec archive cms-ars-3.1-high-microsoft-sql-server-2014-database-stig-overlay
inspec exec <name of generated archive> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --target=winrm://<your_target_host_name_or_ip_address> --user=<target_account_with_administrative_privileges> --password=<password_for_target_account>--reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```

For every successive run, follow these steps to always have the latest version of this overlay and dependent profiles:

```
cd cms-ars-3.1-high-microsoft-sql-server-2014-database-stig-overlay
git pull
cd ..
inspec archive cms-ars-3.1-high-microsoft-sql-server-2014-database-stig-overlay --overwrite
inspec exec <name of generated archive> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --target=winrm://<your_target_host_name_or_ip_address> --user=<target_account_with_administrative_privileges> --password=<password_for_target_account>--reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```

## Using Heimdall for Viewing the JSON Results

The JSON results output file can be loaded into __[heimdall-lite](https://heimdall-lite.mitre.org/)__ for a user-interactive, graphical view of the InSpec results. 

The JSON InSpec results file may also be loaded into a __[full heimdall server](https://github.com/mitre/heimdall)__, allowing for additional functionality such as to store and compare multiple profile runs.

## Authors
* Eugene Aronne - [ejaronne](https://github.com/ejaronne)
* Danny Haynes - [djhaynes](https://github.com/djhaynes)

## Special Thanks
* Rony Xavier - [rx294](https://github.com/rx294)
* Shivani Karikar - [karikarshivani](https://github.com/karikarshivani)

## Contributing and Getting Help
To report a bug or feature request, please open an [issue](https://github.com/CMSgov/cms-ars-3.1-high-microsoft-sql-server-2014-database-stig-overlay/issues/new).

### NOTICE

© 2018-2020 The MITRE Corporation.

Approved for Public Release; Distribution Unlimited. Case Number 18-3678.

### NOTICE 

MITRE hereby grants express written permission to use, reproduce, distribute, modify, and otherwise leverage this software to the extent permitted by the licensed terms provided in the LICENSE.md file included with this project.

### NOTICE  

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.  

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation.

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA  22102-7539, (703) 983-6000.

### NOTICE 

DISA STIGs are published by DISA IASE, see: https://iase.disa.mil/Pages/privacy_policy.aspx
