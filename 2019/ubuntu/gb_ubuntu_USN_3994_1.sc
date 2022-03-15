if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844022" );
	script_version( "2021-08-31T12:01:27+0000" );
	script_cve_id( "CVE-2019-11460" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 12:01:27 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-27 17:29:00 +0000 (Mon, 27 May 2019)" );
	script_tag( name: "creation_date", value: "2019-05-28 02:00:39 +0000 (Tue, 28 May 2019)" );
	script_name( "Ubuntu Update for gnome-desktop3 USN-3994-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.10|UBUNTU19\\.04|UBUNTU18\\.04 LTS)" );
	script_xref( name: "USN", value: "3994-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3994-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gnome-desktop3'
  package(s) announced via the USN-3994-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that gnome-desktop incorrectly confined thumbnailers. If
a user were tricked into downloading a malicious image file, a remote
attacker could possibly combine this issue with another vulnerability to
escape the sandbox and execute arbitrary code." );
	script_tag( name: "affected", value: "'gnome-desktop3' package(s) on Ubuntu 19.04, Ubuntu 18.10, Ubuntu 18.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "libgnome-desktop-3-17", ver: "3.30.1-1ubuntu1.1", rls: "UBUNTU18.10" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "libgnome-desktop-3-17", ver: "3.32.1-1ubuntu1.1", rls: "UBUNTU19.04" ) )){
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
if(release == "UBUNTU18.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "libgnome-desktop-3-17", ver: "3.28.2-0ubuntu1.3", rls: "UBUNTU18.04 LTS" ) )){
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

