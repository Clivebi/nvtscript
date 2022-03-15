if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843999" );
	script_version( "2021-08-31T13:01:28+0000" );
	script_cve_id( "CVE-2019-11454", "CVE-2019-11455" );
	script_tag( name: "cvss_base", value: "5.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 13:01:28 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-05-09 02:00:37 +0000 (Thu, 09 May 2019)" );
	script_name( "Ubuntu Update for monit USN-3971-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.10|UBUNTU19\\.04)" );
	script_xref( name: "USN", value: "3971-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3971-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'monit'
  package(s) announced via the USN-3971-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Zack Flack discovered that Monit incorrectly handled certain input. A remote
authenticated user could exploit this to conduct cross-site scripting (XSS)
attacks. (CVE-2019-11454)

Zack Flack discovered a buffer overread when Monit decoded certain crafted URLs.
An attacker could exploit this to leak potentially sensitive information.
(CVE-2019-11455)" );
	script_tag( name: "affected", value: "'monit' package(s) on Ubuntu 19.04, Ubuntu 18.10." );
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
	if(!isnull( res = isdpkgvuln( pkg: "monit", ver: "1:5.25.2-1ubuntu0.1", rls: "UBUNTU18.10" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "monit", ver: "1:5.25.2-3ubuntu0.1", rls: "UBUNTU19.04" ) )){
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

