if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841616" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-11-08 10:58:25 +0530 (Fri, 08 Nov 2013)" );
	script_cve_id( "CVE-2013-4459" );
	script_tag( name: "cvss_base", value: "3.3" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:P/A:N" );
	script_name( "Ubuntu Update for lightdm USN-2012-1" );
	script_tag( name: "affected", value: "lightdm on Ubuntu 13.10" );
	script_tag( name: "insight", value: "Christian Prim discovered that Light Display Manager
incorrectly applied the AppArmor security profile when the Guest account
is used. A local attacker could use this issue to possibly gain access to
sensitive information." );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2012-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2012-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'lightdm'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU13\\.10" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU13.10"){
	if(( res = isdpkgvuln( pkg: "lightdm", ver: "1.8.4-0ubuntu1", rls: "UBUNTU13.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

