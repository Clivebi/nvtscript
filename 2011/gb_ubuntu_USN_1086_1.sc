if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1086-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840611" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-03-15 14:58:18 +0100 (Tue, 15 Mar 2011)" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:C" );
	script_xref( name: "USN", value: "1086-1" );
	script_cve_id( "CVE-2010-4076", "CVE-2010-4077", "CVE-2010-4158", "CVE-2010-4163", "CVE-2010-4175" );
	script_name( "Ubuntu Update for linux-ec2 vulnerabilities USN-1086-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU10\\.04 LTS" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1086-1" );
	script_tag( name: "affected", value: "linux-ec2 vulnerabilities on Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Dan Rosenberg discovered that multiple terminal ioctls did not correctly
  initialize structure memory. A local attacker could exploit this to
  read portions of kernel stack memory, leading to a loss of privacy.
  (CVE-2010-4076, CVE-2010-4077)

  Dan Rosenberg discovered that the socket filters did not correctly
  initialize structure memory. A local attacker could create malicious
  filters to read portions of kernel stack memory, leading to a loss of
  privacy. (CVE-2010-4158)

  Dan Rosenberg discovered that the SCSI subsystem did not correctly
  validate iov segments. A local attacker with access to a SCSI device
  could send specially crafted requests to crash the system, leading to
  a denial of service. (CVE-2010-4163)

  Dan Rosenberg discovered that the RDS protocol did not correctly check
  ioctl arguments. A local attacker could exploit this to crash the system,
  leading to a denial of service. (CVE-2010-4175)" );
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
	if(( res = isdpkgvuln( pkg: "linux-headers-2.6.32-314-ec2", ver: "2.6.32-314.27", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.32-314-ec2", ver: "2.6.32-314.27", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-ec2-doc", ver: "2.6.32-314.27", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-ec2-source-2.6.32", ver: "2.6.32-314.27", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-headers-2.6.32-314", ver: "2.6.32-314.27", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

