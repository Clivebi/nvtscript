if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843993" );
	script_version( "2021-08-31T11:01:29+0000" );
	script_cve_id( "CVE-2016-7076", "CVE-2017-1000368" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-31 11:01:29 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-30 18:15:00 +0000 (Wed, 30 Sep 2020)" );
	script_tag( name: "creation_date", value: "2019-05-07 02:00:31 +0000 (Tue, 07 May 2019)" );
	script_name( "Ubuntu Update for sudo USN-3968-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU16\\.04 LTS" );
	script_xref( name: "USN", value: "3968-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3968-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'sudo'
  package(s) announced via the USN-3968-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Florian Weimer discovered that Sudo incorrectly handled the noexec
restriction when used with certain applications. A local attacker could
possibly use this issue to bypass configured restrictions and execute
arbitrary commands. (CVE-2016-7076)

It was discovered that Sudo did not properly parse the contents of
/proc/[pid]/stat when attempting to determine its controlling tty. A local
attacker in some configurations could possibly use this to overwrite any
file on the filesystem, bypassing intended permissions. (CVE-2017-1000368)" );
	script_tag( name: "affected", value: "'sudo' package(s) on Ubuntu 16.04 LTS." );
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
if(release == "UBUNTU16.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "sudo", ver: "1.8.16-0ubuntu1.6", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "sudo-ldap", ver: "1.8.16-0ubuntu1.6", rls: "UBUNTU16.04 LTS" ) )){
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

