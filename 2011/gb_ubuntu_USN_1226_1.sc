if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1226-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840769" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-10-10 16:05:48 +0200 (Mon, 10 Oct 2011)" );
	script_tag( name: "cvss_base", value: "3.3" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:P/A:N" );
	script_xref( name: "USN", value: "1226-1" );
	script_cve_id( "CVE-2011-1678", "CVE-2011-2724", "CVE-2011-3585" );
	script_name( "Ubuntu Update for samba USN-1226-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.04 LTS|8\\.04 LTS)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1226-1" );
	script_tag( name: "affected", value: "samba on Ubuntu 10.04 LTS,
  Ubuntu 8.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Dan Rosenberg discovered that Samba incorrectly handled changes to the mtab
  file. A local attacker could use this issue to corrupt the mtab file,
  possibly leading to a denial of service. (CVE-2011-1678)

  Jan Lieskovsky discovered that Samba incorrectly filtered certain strings
  being added to the mtab file. A local attacker could use this issue to
  corrupt the mtab file, possibly leading to a denial of service. This issue
  only affected Ubuntu 10.04 LTS. (CVE-2011-2724)

  Dan Rosenberg discovered that Samba incorrectly handled the mtab lock file.
  A local attacker could use this issue to create a stale lock file, possibly
  leading to a denial of service. (CVE-2011-3585)" );
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
	if(( res = isdpkgvuln( pkg: "smbfs", ver: "2:3.4.7~dfsg-1ubuntu3.8", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU8.04 LTS"){
	if(( res = isdpkgvuln( pkg: "smbfs", ver: "3.0.28a-1ubuntu4.16", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

