if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1296-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840835" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-12-09 10:54:15 +0530 (Fri, 09 Dec 2011)" );
	script_xref( name: "USN", value: "1296-1" );
	script_cve_id( "CVE-2011-2777", "CVE-2011-4578" );
	script_name( "Ubuntu Update for acpid USN-1296-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.10|10\\.04 LTS|11\\.04)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1296-1" );
	script_tag( name: "affected", value: "acpid on Ubuntu 11.04,
  Ubuntu 10.10,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Oliver-Tobias Ripka discovered that an ACPI script incorrectly handled power
  button events. A local attacker could use this to execute arbitrary code, and
  possibly escalate privileges. (CVE-2011-2777)

  Helmut Grohne and Michael Biebl discovered that ACPI scripts were executed with
  a permissive file mode creation mask (umask). A local attacker could read files
  and modify directories created by ACPI scripts that did not set a strict umask.
  (CVE-2011-4578)" );
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
	if(( res = isdpkgvuln( pkg: "acpid", ver: "1.0.10-5ubuntu4.4", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "acpid", ver: "1.0.10-5ubuntu2.5", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "acpid", ver: "1:2.0.7-1ubuntu2.4", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

