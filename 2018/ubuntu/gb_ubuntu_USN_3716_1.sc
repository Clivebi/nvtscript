if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843591" );
	script_version( "$Revision: 14288 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 17:34:17 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2018-07-13 05:49:11 +0200 (Fri, 13 Jul 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for dnsmasq USN-3716-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dnsmasq'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
on the target host." );
	script_tag( name: "insight", value: "This update adds the latest DNSSEC validation
trust anchor required for the upcoming Root Zone KSK Rollover." );
	script_tag( name: "affected", value: "dnsmasq on Ubuntu 16.04 LTS" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "USN", value: "3716-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3716-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU16\\.04 LTS" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "dnsmasq", ver: "2.75-1ubuntu0.16.04.5", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "dnsmasq-base", ver: "2.75-1ubuntu0.16.04.5", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "dnsmasq-utils", ver: "2.75-1ubuntu0.16.04.5", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

