if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1123-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840642" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-05-10 14:04:15 +0200 (Tue, 10 May 2011)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1123-1" );
	script_cve_id( "CVE-2010-3776", "CVE-2010-3778", "CVE-2011-0053", "CVE-2011-0062", "CVE-2011-0051", "CVE-2011-0055", "CVE-2011-0054", "CVE-2011-0056", "CVE-2011-0057", "CVE-2011-0058", "CVE-2010-1585", "CVE-2011-0059", "CVE-2011-0069", "CVE-2011-0070", "CVE-2011-0080", "CVE-2011-0074", "CVE-2011-0075", "CVE-2011-0077", "CVE-2011-0078", "CVE-2011-0072", "CVE-2011-0065", "CVE-2011-0066", "CVE-2011-0073", "CVE-2011-0067", "CVE-2011-0071", "CVE-2011-1202" );
	script_name( "Ubuntu Update for xulrunner-1.9.1 USN-1123-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU9\\.10" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1123-1" );
	script_tag( name: "affected", value: "xulrunner-1.9.1 on Ubuntu 9.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "A large number of security issues were discovered in the Gecko rendering
  engine. If a user were tricked into viewing a malicious website, a remote
  attacker could exploit a variety of issues related to web browser security,
  including cross-site scripting attacks, denial of service attacks, and
  arbitrary code execution." );
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
if(release == "UBUNTU9.10"){
	if(( res = isdpkgvuln( pkg: "xulrunner-1.9.1", ver: "1.9.1.19+build2+nobinonly-0ubuntu0.9.10.1", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

