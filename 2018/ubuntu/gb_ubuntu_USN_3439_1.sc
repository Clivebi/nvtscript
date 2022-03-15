if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843791" );
	script_version( "2021-06-04T11:00:20+0000" );
	script_cve_id( "CVE-2017-0898", "CVE-2017-0899", "CVE-2017-0900", "CVE-2017-0901", "CVE-2017-10784", "CVE-2017-14033", "CVE-2017-14064", "CVE-2017-10748" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-06-04 11:00:20 +0000 (Fri, 04 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-31 10:29:00 +0000 (Wed, 31 Oct 2018)" );
	script_tag( name: "creation_date", value: "2018-10-26 06:20:37 +0200 (Fri, 26 Oct 2018)" );
	script_name( "Ubuntu Update for ruby1.9.1 USN-3439-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU14\\.04 LTS" );
	script_xref( name: "USN", value: "3439-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3439-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ruby1.9.1'
  package(s) announced via the USN-3439-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that Ruby incorrectly handled certain inputs.
An attacker could use this to cause a buffer overrun.
(CVE-2017-0898)

Yusuke Endoh discovered that Ruby incorrectly handled certain files.
An attacker could use this to execute terminal escape sequences.
(CVE-2017-0899)

Yusuke Endoh discovered that Ruby incorrectly handled certain inputs.
An attacker could use this to cause a denial of service.
(CVE-2017-0900)

It was discovered that Ruby incorrectly handled certain files.
An attacker could use this to overwrite any file on the filesystem.
(CVE-2017-0901)

It was discovered that Ruby incorrectly handled certain inputs.
An attacker could use this to execute arbitrary code.
(CVE-2017-10784)

It was discovered that Ruby incorrectly handled certain inputs.
An attacker could use this to cause a denial of service.
(CVE-2017-14033)

It was discovered that Ruby incorrectly handled certain files.
An attacker could use this to expose sensitive information.
(CVE-2017-14064)" );
	script_tag( name: "affected", value: "ruby1.9.1 on Ubuntu 14.04 LTS." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libruby1.9.1", ver: "1.9.3.484-2ubuntu1.5", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "ruby1.9.1", ver: "1.9.3.484-2ubuntu1.5", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "ruby1.9.3", ver: "1.9.3.484-2ubuntu1.5", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

