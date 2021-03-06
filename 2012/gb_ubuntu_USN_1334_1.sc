if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1334-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840868" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-01-20 11:00:26 +0530 (Fri, 20 Jan 2012)" );
	script_cve_id( "CVE-2011-0216", "CVE-2011-2821", "CVE-2011-2834", "CVE-2011-3905", "CVE-2011-3919" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1334-1" );
	script_name( "Ubuntu Update for libxml2 USN-1334-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.10|10\\.04 LTS|11\\.04|8\\.04 LTS)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1334-1" );
	script_tag( name: "affected", value: "libxml2 on Ubuntu 11.04,
  Ubuntu 10.10,
  Ubuntu 10.04 LTS,
  Ubuntu 8.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "It was discovered that libxml2 contained an off by one error. If a user or
  application linked against libxml2 were tricked into opening a specially
  crafted XML file, an attacker could cause the application to crash or
  possibly execute arbitrary code with the privileges of the user invoking
  the program. (CVE-2011-0216)

  It was discovered that libxml2 is vulnerable to double-free conditions
  when parsing certain XML documents. This could allow a remote attacker to
  cause a denial of service. (CVE-2011-2821, CVE-2011-2834)

  It was discovered that libxml2 did not properly detect end of file when
  parsing certain XML documents. An attacker could exploit this to crash
  applications linked against libxml2. (CVE-2011-3905)

  It was discovered that libxml2 did not properly decode entity references
  with long names. If a user or application linked against libxml2 were
  tricked into opening a specially crafted XML file, an attacker could cause
  the application to crash or possibly execute arbitrary code with the
  privileges of the user invoking the program. (CVE-2011-3919)" );
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
if(release == "UBUNTU10.10"){
	if(( res = isdpkgvuln( pkg: "libxml2", ver: "2.7.7.dfsg-4ubuntu0.3", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libxml2", ver: "2.7.6.dfsg-1ubuntu1.3", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "libxml2", ver: "2.7.8.dfsg-2ubuntu0.2", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU8.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libxml2", ver: "2.6.31.dfsg-2ubuntu1.7", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

