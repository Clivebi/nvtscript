if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1372-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840907" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-03-09 18:56:11 +0530 (Fri, 09 Mar 2012)" );
	script_cve_id( "CVE-2012-1053", "CVE-2012-1054" );
	script_xref( name: "USN", value: "1372-1" );
	script_name( "Ubuntu Update for puppet USN-1372-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.10|10\\.04 LTS|11\\.04)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1372-1" );
	script_tag( name: "affected", value: "puppet on Ubuntu 11.04,
  Ubuntu 10.10,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "It was discovered that Puppet did not drop privileges when executing
  commands as different users. If an attacker had control of the execution
  manifests or the executed command, this could be used to execute code with
  elevated group permissions (typically root). (CVE-2012-1053)

  It was discovered that Puppet unsafely opened files when the k5login type
  is used to manage files. A local attacker could exploit this to overwrite
  arbitrary files and escalate privileges. (CVE-2012-1054)" );
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
	if(( res = isdpkgvuln( pkg: "puppet-common", ver: "2.6.1-0ubuntu2.6", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "puppet-common", ver: "0.25.4-2ubuntu6.6", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "puppet-common", ver: "2.6.4-2ubuntu2.8", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

