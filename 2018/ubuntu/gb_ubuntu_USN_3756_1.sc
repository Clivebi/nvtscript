if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843629" );
	script_version( "2021-06-04T02:00:20+0000" );
	script_tag( name: "last_modification", value: "2021-06-04 02:00:20 +0000 (Fri, 04 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-08-28 07:19:45 +0200 (Tue, 28 Aug 2018)" );
	script_cve_id( "CVE-2018-3646", "CVE-2018-3639", "CVE-2018-3640" );
	script_tag( name: "cvss_base", value: "4.7" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for intel-microcode USN-3756-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'intel-microcode'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that memory present in the L1 data cache of an Intel CPU
core may be exposed to a malicious process that is executing on the CPU
core. This vulnerability is also known as L1 Terminal Fault (L1TF). A local
attacker in a guest virtual machine could use this to expose sensitive
information (memory from other guests or the host OS). (CVE-2018-3646)

Jann Horn and Ken Johnson discovered that microprocessors utilizing
speculative execution of a memory read may allow unauthorized memory reads
via a sidechannel attack. This flaw is known as Spectre Variant 4. A local
attacker could use this to expose sensitive information, including kernel
memory. (CVE-2018-3639)

Zdenek Sojka, Rudolf Marek, Alex Zuepke, and Innokentiy Sennovskiy
discovered that microprocessors that perform speculative reads of
system registers may allow unauthorized disclosure of system parameters
via a sidechannel attack. This vulnerability is also known as Rogue
System Register Read (RSRE). An attacker could use this to expose
sensitive information. (CVE-2018-3640)" );
	script_tag( name: "affected", value: "intel-microcode on Ubuntu 18.04 LTS,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "USN", value: "3756-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3756-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|18\\.04 LTS|16\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "intel-microcode", ver: "3.20180807a.0ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU18.04 LTS"){
	if(( res = isdpkgvuln( pkg: "intel-microcode", ver: "3.20180807a.0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "intel-microcode", ver: "3.20180807a.0ubuntu0.16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

