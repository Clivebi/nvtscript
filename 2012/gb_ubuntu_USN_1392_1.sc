if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1392-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840925" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-03-09 10:26:02 +0530 (Fri, 09 Mar 2012)" );
	script_cve_id( "CVE-2011-2182" );
	script_xref( name: "USN", value: "1392-1" );
	script_name( "Ubuntu Update for linux-fsl-imx51 USN-1392-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU10\\.04 LTS" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1392-1" );
	script_tag( name: "affected", value: "linux-fsl-imx51 on Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Ben Hutchings reported a flaw in the kernel's handling of corrupt LDM
  partitions. A local user could exploit this to cause a denial of service or
  escalate privileges." );
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
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.31-612-imx51", ver: "2.6.31-612.33", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

