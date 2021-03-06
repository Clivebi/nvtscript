if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1377-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840923" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-03-07 11:20:13 +0530 (Wed, 07 Mar 2012)" );
	script_cve_id( "CVE-2010-0541", "CVE-2011-0188", "CVE-2011-1004", "CVE-2011-1005", "CVE-2011-2686", "CVE-2011-2705", "CVE-2011-4815" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_xref( name: "USN", value: "1377-1" );
	script_name( "Ubuntu Update for ruby1.8 USN-1377-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.10|10\\.04 LTS|11\\.04)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1377-1" );
	script_tag( name: "affected", value: "ruby1.8 on Ubuntu 11.04,
  Ubuntu 10.10,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Drew Yao discovered that the WEBrick HTTP server was vulnerable to cross-site
  scripting attacks when displaying error pages. A remote attacker could use this
  flaw to run arbitrary web script. (CVE-2010-0541)

  Drew Yao discovered that Ruby's BigDecimal module did not properly allocate
  memory on 64-bit platforms. An attacker could use this flaw to cause a denial
  of service or possibly execute arbitrary code with user privileges.
  (CVE-2011-0188)

  Nicholas Jefferson discovered that the FileUtils.remove_entry_secure method in
  Ruby did not properly remove non-empty directories. An attacker could use this
  flaw to possibly delete arbitrary files. (CVE-2011-1004)

  It was discovered that Ruby incorrectly allowed untainted strings to be
  modified in protective safe levels. An attacker could use this flaw to bypass
  intended access restrictions. (CVE-2011-1005)

  Eric Wong discovered that Ruby does not properly reseed its pseudorandom number
  generator when creating child processes. An attacker could use this flaw to
  gain knowledge of the random numbers used in other Ruby child processes.
  (CVE-2011-2686)

  Eric Wong discovered that the SecureRandom module in Ruby did not properly seed
  its pseudorandom number generator. An attacker could use this flaw to gain
  knowledge of the random numbers used by another Ruby process with the same
  process ID number. (CVE-2011-2705)

  Alexander Klink and Julian Walde discovered that Ruby computed hash values
  without restricting the ability to trigger hash collisions predictably. A
  remote attacker could cause a denial of service by crafting values used in hash
  tables. (CVE-2011-4815)" );
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
	if(( res = isdpkgvuln( pkg: "libruby1.8", ver: "1.8.7.299-2ubuntu0.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "ruby1.8", ver: "1.8.7.299-2ubuntu0.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libruby1.8", ver: "1.8.7.249-2ubuntu0.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "ruby1.8", ver: "1.8.7.249-2ubuntu0.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "libruby1.8", ver: "1.8.7.302-2ubuntu0.1", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "ruby1.8", ver: "1.8.7.302-2ubuntu0.1", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

