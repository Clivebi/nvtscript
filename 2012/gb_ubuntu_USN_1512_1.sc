if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1512-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841089" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-07-23 10:47:25 +0530 (Mon, 23 Jul 2012)" );
	script_cve_id( "CVE-2012-3413" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_xref( name: "USN", value: "1512-1" );
	script_name( "Ubuntu Update for kdepim USN-1512-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.04 LTS|11\\.10)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1512-1" );
	script_tag( name: "affected", value: "kdepim on Ubuntu 12.04 LTS,
  Ubuntu 11.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "It was discovered that KDE PIM html renderer incorrectly enabled
  JavaScript, Java and Plugins. A remote attacker could use this flaw to send
  an email with embedded JavaScript that possibly executes when opened." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
	if(( res = isdpkgvuln( pkg: "kdepim", ver: "4.8.4a-0ubuntu0.3", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.10"){
	if(( res = isdpkgvuln( pkg: "kdepim", ver: "4.7.4+git111222-0ubuntu0.3", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

