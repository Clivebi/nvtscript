if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841828" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-05-26 15:59:00 +0530 (Mon, 26 May 2014)" );
	script_cve_id( "CVE-2014-3775" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Ubuntu Update for libgadu USN-2215-1" );
	script_tag( name: "affected", value: "libgadu on Ubuntu 13.10,
  Ubuntu 12.04 LTS" );
	script_tag( name: "insight", value: "It was discovered that libgadu incorrectly handled certain
messages from file relay servers. A malicious remote server or a man in the
middle could use this issue to cause applications using libgadu to crash,
resulting in a denial of service, or possibly execute arbitrary code." );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2215-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2215-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libgadu'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.04 LTS|13\\.10)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libgadu3", ver: "1:1.11.1-1ubuntu0.2", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU13.10"){
	if(( res = isdpkgvuln( pkg: "libgadu3", ver: "1:1.11.2-1ubuntu1.2", rls: "UBUNTU13.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

