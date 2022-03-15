if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841894" );
	script_version( "2020-02-11T08:37:57+0000" );
	script_tag( name: "last_modification", value: "2020-02-11 08:37:57 +0000 (Tue, 11 Feb 2020)" );
	script_tag( name: "creation_date", value: "2014-07-21 16:46:57 +0530 (Mon, 21 Jul 2014)" );
	script_cve_id( "CVE-2014-3230" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Ubuntu Update for liblwp-protocol-https-perl USN-2292-1" );
	script_tag( name: "affected", value: "liblwp-protocol-https-perl on Ubuntu 14.04 LTS" );
	script_tag( name: "insight", value: "It was discovered that the LWP::Protocol::https perl module
incorrectly disabled peer certificate verification completely when only hostname
verification was requested to be disabled. If a remote attacker were able
to perform a man-in-the-middle attack, this flaw could possibly be
exploited in certain scenarios to alter or compromise confidential
information in applications that used the LWP::Protocol::https module." );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2292-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2292-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'liblwp-protocol-https-perl'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU14\\.04 LTS" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "liblwp-protocol-https-perl", ver: "6.04-2ubuntu0.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

