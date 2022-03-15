if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844646" );
	script_version( "2021-07-13T02:01:14+0000" );
	script_cve_id( "CVE-2014-6053", "CVE-2018-7225", "CVE-2019-15681", "CVE-2020-14397", "CVE-2020-14402", "CVE-2020-14403", "CVE-2020-14404" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-13 02:01:14 +0000 (Tue, 13 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-23 13:15:00 +0000 (Fri, 23 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-10-08 03:00:40 +0000 (Thu, 08 Oct 2020)" );
	script_name( "Ubuntu: Security Advisory for vino (USN-4573-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.04 LTS|UBUNTU16\\.04 LTS|UBUNTU20\\.04 LTS)" );
	script_xref( name: "USN", value: "4573-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-October/005683.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'vino'
  package(s) announced via the USN-4573-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Nicolas Ruff discovered that Vino incorrectly handled large ClientCutText
messages. A remote attacker could use this issue to cause the server to
crash, resulting in a denial of service. (CVE-2014-6053)

It was discovered that Vino incorrectly handled certain packet lengths. A
remote attacker could possibly use this issue to obtain sensitive
information, cause a denial of service, or execute arbitrary code.
(CVE-2018-7225)

Pavel Cheremushkin discovered that an information disclosure vulnerability
existed in Vino when sending a ServerCutText message. An attacker could
possibly use this issue to expose sensitive information. (CVE-2019-15681)

It was discovered that Vino incorrectly handled region clipping. A remote
attacker could possibly use this issue to cause Vino to crash, resulting in
a denial of service. (CVE-2020-14397)

It was discovered that Vino incorrectly handled encodings. A remote
attacker could use this issue to cause Vino to crash, resulting in a denial
of service, or possibly execute arbitrary code. (CVE-2020-14402,
CVE-2020-14403, CVE-2020-14404)" );
	script_tag( name: "affected", value: "'vino' package(s) on Ubuntu 20.04 LTS, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
report = "";
if(release == "UBUNTU18.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "vino", ver: "3.22.0-3ubuntu1.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "vino", ver: "3.8.1-0ubuntu9.3", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
if(release == "UBUNTU20.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "vino", ver: "3.22.0-5ubuntu2.1", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

