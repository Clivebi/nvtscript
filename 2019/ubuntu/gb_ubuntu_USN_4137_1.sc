if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844183" );
	script_version( "2021-08-31T12:01:27+0000" );
	script_cve_id( "CVE-2019-11779" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 12:01:27 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-09-23 21:15:00 +0000 (Mon, 23 Sep 2019)" );
	script_tag( name: "creation_date", value: "2019-09-24 02:00:46 +0000 (Tue, 24 Sep 2019)" );
	script_name( "Ubuntu Update for mosquitto USN-4137-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU19\\.04" );
	script_xref( name: "USN", value: "4137-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2019-September/005129.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mosquitto'
  package(s) announced via the USN-4137-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that Mosquitto incorrectly handled certain specially crafted
input and network packets. A remote attacker could use this to cause a denial
of service." );
	script_tag( name: "affected", value: "'mosquitto' package(s) on Ubuntu 19.04." );
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
if(release == "UBUNTU19.04"){
	if(!isnull( res = isdpkgvuln( pkg: "libmosquitto1", ver: "1.5.7-1ubuntu0.1", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libmosquittopp1", ver: "1.5.7-1ubuntu0.1", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mosquitto", ver: "1.5.7-1ubuntu0.1", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "mosquitto-clients", ver: "1.5.7-1ubuntu0.1", rls: "UBUNTU19.04" ) )){
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

