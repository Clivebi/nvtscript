if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843994" );
	script_version( "2021-08-31T12:01:27+0000" );
	script_cve_id( "CVE-2019-3500" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-31 12:01:27 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-06 18:29:00 +0000 (Mon, 06 May 2019)" );
	script_tag( name: "creation_date", value: "2019-05-07 02:00:33 +0000 (Tue, 07 May 2019)" );
	script_name( "Ubuntu Update for aria2 USN-3965-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.10|UBUNTU19\\.04)" );
	script_xref( name: "USN", value: "3965-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3965-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'aria2'
  package(s) announced via the USN-3965-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Dhiraj Mishra discovered that aria2 incorrectly stored authentication
information. A local attacker could possibly use this issue to obtain
credentials." );
	script_tag( name: "affected", value: "'aria2' package(s) on Ubuntu 19.04, Ubuntu 18.10." );
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
if(release == "UBUNTU18.10"){
	if(!isnull( res = isdpkgvuln( pkg: "aria2", ver: "1.34.0-2ubuntu0.1", rls: "UBUNTU18.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libaria2-0", ver: "1.34.0-2ubuntu0.1", rls: "UBUNTU18.10" ) )){
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
if(release == "UBUNTU19.04"){
	if(!isnull( res = isdpkgvuln( pkg: "aria2", ver: "1.34.0-3ubuntu0.1", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libaria2-0", ver: "1.34.0-3ubuntu0.1", rls: "UBUNTU19.04" ) )){
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
