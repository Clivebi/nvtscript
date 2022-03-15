if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1614-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841196" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-10-23 09:29:09 +0530 (Tue, 23 Oct 2012)" );
	script_cve_id( "CVE-2012-4464", "CVE-2012-4466", "CVE-2012-4522" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_xref( name: "USN", value: "1614-1" );
	script_name( "Ubuntu Update for ruby1.9.1 USN-1614-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU12\\.04 LTS" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1614-1" );
	script_tag( name: "affected", value: "ruby1.9.1 on Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Tyler Hicks and Shugo Maeda discovered that Ruby incorrectly allowed untainted
  strings to be modified in protective safe levels. An attacker could use this
  flaw to bypass intended access restrictions. USN-1602-1 fixed these
  vulnerabilities in other Ubuntu releases. This update provides the
  corresponding updates for Ubuntu 12.10. (CVE-2012-4464, CVE-2012-4466)

  Peter Bex discovered that Ruby incorrectly handled file path strings when
  opening files. An attacker could use this flaw to open or create unexpected
  files. (CVE-2012-4522)" );
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
	if(( res = isdpkgvuln( pkg: "libruby1.9.1", ver: "1.9.3.0-1ubuntu2.4", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

