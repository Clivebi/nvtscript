if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1232-2/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840774" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-10-21 16:31:29 +0200 (Fri, 21 Oct 2011)" );
	script_xref( name: "USN", value: "1232-2" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:C/I:C/A:C" );
	script_cve_id( "CVE-2010-4818", "CVE-2010-4819", "CVE-2011-4028", "CVE-2011-4029" );
	script_name( "Ubuntu Update for xorg-server USN-1232-2" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU10\\.04 LTS" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1232-2" );
	script_tag( name: "affected", value: "xorg-server on Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "USN-1232-1 fixed vulnerabilities in the X.Org X server. A regression was
  found on Ubuntu 10.04 LTS that affected GLX support.

  This update temporarily disables the fix for CVE-2010-4818 that introduced
  the regression.

  We apologize for the inconvenience.

  Original advisory details:

  It was discovered that the X server incorrectly handled certain malformed
  input. An authorized attacker could exploit this to cause the X server to
  crash, leading to a denial or service, or possibly execute arbitrary code
  with root privileges. This issue only affected Ubuntu 10.04 LTS and 10.10.
  (CVE-2010-4818)

  It was discovered that the X server incorrectly handled certain malformed
  input. An authorized attacker could exploit this to cause the X server to
  crash, leading to a denial or service, or possibly read arbitrary data from
  the X server process. This issue only affected Ubuntu 10.04 LTS.
  (CVE-2010-4819)

  Vladz discovered that the X server incorrectly handled lock files. A local
  attacker could use this flaw to determine if a file existed or not.
  (CVE-2011-4028)

  Vladz discovered that the X server incorrectly handled setting lock file
  permissions. A local attacker could use this flaw to gain read permissions
  on arbitrary files and view sensitive information. (CVE-2011-4029)" );
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
	if(( res = isdpkgvuln( pkg: "xserver-xorg-core", ver: "2:1.7.6-2ubuntu7.9", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

