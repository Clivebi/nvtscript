if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882743" );
	script_version( "2021-09-13T14:16:31+0000" );
	script_tag( name: "last_modification", value: "2021-09-13 14:16:31 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-06-23 07:17:13 +0200 (Fri, 23 Jun 2017)" );
	script_cve_id( "CVE-2017-1000368", "CVE-2017-1000367" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-29 19:29:00 +0000 (Wed, 29 May 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for sudo CESA-2017:1574 centos7" );
	script_tag( name: "summary", value: "Check the version of sudo" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The sudo packages contain the sudo utility
which allows system administrators to provide certain users with the permission
to execute privileged commands, which are used for system management purposes,
without having to log in as root.

Security Fix(es):

  * It was found that the original fix for CVE-2017-1000367 was incomplete. A
flaw was found in the way sudo parsed tty information from the process
status file in the proc filesystem. A local user with privileges to execute
commands via sudo could use this flaw to escalate their privileges to root.
(CVE-2017-1000368)" );
	script_tag( name: "affected", value: "sudo on CentOS 7" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2017:1574" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2017-June/022470.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS7"){
	if(( res = isrpmvuln( pkg: "sudo", rpm: "sudo~1.8.6p7~23.el7_3", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "sudo-devel", rpm: "sudo-devel~1.8.6p7~23.el7_3", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
