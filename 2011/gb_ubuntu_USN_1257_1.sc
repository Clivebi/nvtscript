if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1257-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840799" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-11-11 09:55:29 +0530 (Fri, 11 Nov 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "USN", value: "1257-1" );
	script_cve_id( "CVE-2011-3601", "CVE-2011-3602", "CVE-2011-3604", "CVE-2011-3605" );
	script_name( "Ubuntu Update for radvd USN-1257-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.10|10\\.04 LTS|11\\.04)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1257-1" );
	script_tag( name: "affected", value: "radvd on Ubuntu 11.04,
  Ubuntu 10.10,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Vasiliy Kulikov discovered that radvd incorrectly parsed the
  ND_OPT_DNSSL_INFORMATION option. A remote attacker could exploit this with
  a specially-crafted request and cause the radvd daemon to crash, or
  possibly execute arbitrary code. The default compiler options for affected
  releases should reduce the vulnerability to a denial of service. This issue
  only affected Ubuntu 11.04 and 11.10. (CVE-2011-3601)

  Vasiliy Kulikov discovered that radvd incorrectly filtered interface names
  when creating certain files. A local attacker could exploit this to
  overwrite certain files on the system, bypassing intended permissions.
  (CVE-2011-3602)

  Vasiliy Kulikov discovered that radvd incorrectly handled certain lengths.
  A remote attacker could exploit this to cause the radvd daemon to crash,
  resulting in a denial of service. (CVE-2011-3604)

  Vasiliy Kulikov discovered that radvd incorrectly handled delays when used
  in unicast mode, which is not the default in Ubuntu. If used in unicast
  mode, a remote attacker could cause radvd outages, resulting in a denial of
  service. (CVE-2011-3605)" );
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
	if(( res = isdpkgvuln( pkg: "radvd", ver: "1:1.6-1ubuntu0.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "radvd", ver: "1:1.3-1.1ubuntu0.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "radvd", ver: "1:1.7-1ubuntu0.1", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

