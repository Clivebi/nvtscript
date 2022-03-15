if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1265-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840807" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-11-18 09:47:10 +0530 (Fri, 18 Nov 2011)" );
	script_xref( name: "USN", value: "1265-1" );
	script_cve_id( "CVE-2011-4405" );
	script_name( "Ubuntu Update for system-config-printer USN-1265-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU11\\.04" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1265-1" );
	script_tag( name: "affected", value: "system-config-printer on Ubuntu 11.04" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Marc Deslauriers discovered that system-config-printer's cupshelpers
  scripts used by the Ubuntu automatic printer driver download service
  queried the OpenPrinting database using an insecure connection. If a remote
  attacker were able to perform a man-in-the-middle attack, this flaw could
  be exploited to install altered packages and repositories." );
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
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "python-cupshelpers", ver: "1.3.1+20110222-0ubuntu16.5", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

