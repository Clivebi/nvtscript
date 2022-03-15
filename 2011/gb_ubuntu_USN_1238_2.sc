if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1238-2/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840784" );
	script_cve_id( "CVE-2011-3872" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:P/A:N" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-10-31 13:45:00 +0100 (Mon, 31 Oct 2011)" );
	script_xref( name: "USN", value: "1238-2" );
	script_name( "Ubuntu Update for puppet USN-1238-2" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU11\\.04" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1238-2" );
	script_tag( name: "affected", value: "puppet on Ubuntu 11.04" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "USN-1238-1 fixed vulnerabilities in Puppet. The upstream patch introduced a
  regression in Ubuntu 11.04 when executing certain commands. This update
  fixes the problem.

  We apologize for the inconvenience.

  Original advisory details:

  It was discovered that Puppet incorrectly handled the non-default
  'certdnsnames' option when generating certificates. If this setting was
  added to puppet.conf, the puppet master's DNS alt names were added to the
  X.509 Subject Alternative Name field of all certificates, not just the
  puppet master's certificate. An attacker that has an incorrect agent
  certificate in his possession can use it to impersonate the puppet master
  in a man-in-the-middle attack." );
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
	if(( res = isdpkgvuln( pkg: "puppet-common", ver: "2.6.4-2ubuntu2.6", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

