if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844138" );
	script_version( "2021-08-31T13:01:28+0000" );
	script_cve_id( "CVE-2019-13377" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-31 13:01:28 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-09-29 23:15:00 +0000 (Sun, 29 Sep 2019)" );
	script_tag( name: "creation_date", value: "2019-08-15 02:00:40 +0000 (Thu, 15 Aug 2019)" );
	script_name( "Ubuntu Update for wpa USN-4098-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.04 LTS|UBUNTU19\\.04)" );
	script_xref( name: "USN", value: "4098-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-4098-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'wpa'
  package(s) announced via the USN-4098-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that wpa_supplicant and hostapd were vulnerable to a side
channel attack against EAP-pwd. A remote attacker could possibly use this
issue to recover certain passwords." );
	script_tag( name: "affected", value: "'wpa' package(s) on Ubuntu 19.04, Ubuntu 18.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "hostapd", ver: "2:2.6-15ubuntu2.4", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "wpasupplicant", ver: "2:2.6-15ubuntu2.4", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "hostapd", ver: "2:2.6-21ubuntu3.2", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "wpasupplicant", ver: "2:2.6-21ubuntu3.2", rls: "UBUNTU19.04" ) )){
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

