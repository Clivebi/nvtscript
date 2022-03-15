if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.845048" );
	script_version( "2021-09-22T08:01:20+0000" );
	script_cve_id( "CVE-2018-10852", "CVE-2018-16838", "CVE-2019-3811", "CVE-2021-3621" );
	script_tag( name: "cvss_base", value: "5.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-22 08:01:20 +0000 (Wed, 22 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-15 13:28:00 +0000 (Thu, 15 Oct 2020)" );
	script_tag( name: "creation_date", value: "2021-09-09 01:00:40 +0000 (Thu, 09 Sep 2021)" );
	script_name( "Ubuntu: Security Advisory for sssd (USN-5067-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.04 LTS|UBUNTU20\\.04 LTS)" );
	script_xref( name: "Advisory-ID", value: "USN-5067-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-September/006171.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'sssd'
  package(s) announced via the USN-5067-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Jakub Hrozek discovered that SSSD incorrectly handled file permissions. A
local attacker could possibly use this issue to read the sudo rules
available for any user. This issue only affected Ubuntu 18.04 LTS.
(CVE-2018-10852)

It was discovered that SSSD incorrectly handled Group Policy Objects. When
SSSD is configured with too strict permissions causing the GPO to not be
readable, SSSD will allow all authenticated users to login instead of being
denied, contrary to expectations. This issue only affected Ubuntu 18.04
LTS. (CVE-2018-16838)

It was discovered that SSSD incorrectly handled users with no home
directory set. When no home directory was set, SSSD would return the root
directory instead of an empty string, possibly bypassing security measures.
This issue only affected Ubuntu 18.04 LTS. (CVE-2019-3811)

Cedric Buissart discovered that SSSD incorrectly handled the sssctl
command. In certain environments, a local user could use this issue to
execute arbitrary commands and possibly escalate privileges.
(CVE-2021-3621)" );
	script_tag( name: "affected", value: "'sssd' package(s) on Ubuntu 20.04 LTS, Ubuntu 18.04 LTS." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "UBUNTU18.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "sssd", ver: "1.16.1-1ubuntu1.8", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
if(release == "UBUNTU20.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "sssd", ver: "2.2.3-3ubuntu0.7", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

