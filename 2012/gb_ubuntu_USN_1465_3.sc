if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1465-3/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841027" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-06-08 10:13:54 +0530 (Fri, 08 Jun 2012)" );
	script_cve_id( "CVE-2011-4409" );
	script_xref( name: "USN", value: "1465-3" );
	script_name( "Ubuntu Update for ubuntuone-client USN-1465-3" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU10\\.04 LTS" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1465-3" );
	script_tag( name: "affected", value: "ubuntuone-client on Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "USN-1465-1 fixed vulnerabilities in Ubuntu One Client. The update failed to
  install on certain Ubuntu 10.04 LTS systems that had a legacy Python 2.5
  package installed. This update fixes the problem.

  We apologize for the inconvenience.

  Original advisory details:

  It was discovered that the Ubuntu One Client incorrectly validated server
  certificates when using HTTPS connections. If a remote attacker were able
  to perform a man-in-the-middle attack, this flaw could be exploited to
  alter or compromise confidential information." );
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
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "python-ubuntuone-client", ver: "1.2.2-0ubuntu2.3", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

