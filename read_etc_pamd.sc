if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150130" );
	script_version( "2020-07-29T11:15:13+0000" );
	script_tag( name: "last_modification", value: "2020-07-29 11:15:13 +0000 (Wed, 29 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-02-12 08:01:49 +0000 (Wed, 12 Feb 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: Read password configuration files (KB)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "gather-package-list.sc", "compliance_tests.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_xref( name: "URL", value: "https://linux.die.net/man/5/pam.d" );
	script_tag( name: "summary", value: "When a PAM aware privilege granting application is started, it
activates its attachment to the PAM-API. This activation performs a number of tasks, the most
important being the reading of the configuration file(s): /etc/pam.conf. Alternatively, this may be
the contents of the /etc/pam.d/ directory. The presence of this directory will cause Linux-PAM to
ignore /etc/pam.conf.

These files list the PAMs that will do the authentication tasks required by this service, and the
appropriate behavior of the PAM-API in the event that individual PAMs fail.

  - account: this module type performs non-authentication based account management. It is typically
used to restrict/permit access to a service based on the time of day, currently available system
resources (maximum number of users) or perhaps the location of the applicant user -- 'root' login
only on the console.

  - auth: this module type provides two aspects of authenticating the user. Firstly, it establishes
that the user is who they claim to be, by instructing the application to prompt the user for a
password or other means of identification. Secondly, the module can grant group membership or other
rivileges through its credential granting properties.

  - password: this module type is required for updating the authentication token associated with the
user. Typically, there is one module for each 'challenge/response' based authentication (auth) type.

  - pwhistory: this module saves the last passwords for each user in order to force password change
history and keep the user from alternating between the same password too frequently.

  - unix: this is the standard Unix authentication module. It uses standard calls from the system's
libraries to retrieve and set account information as well as authentication. Usually this is obtained
from the /etc/passwd and the /etc/shadow file as well if shadow is enabled.

Note: This script read files /etc/pam.d/common-auth, /etc/pam.d/password-auth, /etc/pam.d/system-auth,
/etc/pam.d/common-password, /etc/pam.d/su and /etc/security/pwquality.conf and only stores information
for other Policy Controls." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("policy_functions.inc.sc");
if(!get_kb_item( "login/SSH/success" ) || !sock = ssh_login_or_reuse_connection()){
	set_kb_item( name: "Policy/linux/etc/pam.d/ERROR", value: TRUE );
	set_kb_item( name: "Policy/linux/etc/pam.d/stat/ERROR", value: TRUE );
	exit( 0 );
}
files = make_list( "/etc/pam.d/common-auth",
	 "/etc/pam.d/password-auth",
	 "/etc/pam.d/system-auth",
	 "/etc/pam.d/common-password",
	 "/etc/pam.d/su",
	 "/etc/security/pwquality.conf" );
for file in files {
	policy_linux_stat_file( socket: sock, file: file );
	policy_linux_file_content( socket: sock, file: file );
}
exit( 0 );

