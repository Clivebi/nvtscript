if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842760" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-05-17 16:25:18 +0200 (Tue, 17 May 2016)" );
	script_cve_id( "CVE-2016-4008" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for libtasn1-6 USN-2957-2" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libtasn1-6'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "USN-2957-1 fixed a vulnerability in Libtasn1.
  This update provides the corresponding update for Ubuntu 16.04 LTS.

  Original advisory details:

  Pascal Cuoq and Miod Vallat discovered that Libtasn1 incorrectly handled
  certain malformed DER certificates. A remote attacker could possibly use
  this issue to cause applications using Libtasn1 to hang, resulting in a
  denial of service." );
	script_tag( name: "affected", value: "libtasn1-6 on Ubuntu 16.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2957-2" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2957-2/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
	if(( res = isdpkgvuln( pkg: "libtasn1-6:i386", ver: "4.7-3ubuntu0.16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libtasn1-6:amd64", ver: "4.7-3ubuntu0.16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

