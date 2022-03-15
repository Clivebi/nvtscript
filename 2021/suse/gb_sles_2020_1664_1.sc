if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.1664.1" );
	script_cve_id( "CVE-2020-13401" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:01 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-27 00:15:00 +0000 (Thu, 27 Aug 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:1664-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:1664-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20201664-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'containerd, docker, docker-runc, golang-github-docker-libnetwork' package(s) announced via the SUSE-SU-2020:1664-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for containerd, docker, docker-runc,
golang-github-docker-libnetwork fixes the following issues: Docker was updated to 19.03.11-ce runc was updated to version 1.0.0-rc10 containerd was updated to version 1.2.13

CVE-2020-13401: Fixed an issue where an attacker with CAP_NET_RAW
 capability, could have crafted IPv6 router advertisements, and spoof
 external IPv6 hosts, resulting in obtaining sensitive information or
 causing denial
 of service (bsc#1172377)." );
	script_tag( name: "affected", value: "'containerd, docker, docker-runc, golang-github-docker-libnetwork' package(s) on SUSE Linux Enterprise Module for Containers 12." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "SLES12.0"){
	if(!isnull( res = isrpmvuln( pkg: "containerd", rpm: "containerd~1.2.13~16.29.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "docker", rpm: "docker~19.03.11_ce~98.54.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "docker-debuginfo", rpm: "docker-debuginfo~19.03.11_ce~98.54.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "docker-libnetwork", rpm: "docker-libnetwork~0.7.0.1+gitr2902_153d0769a118~31.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "docker-libnetwork-debuginfo", rpm: "docker-libnetwork-debuginfo~0.7.0.1+gitr2902_153d0769a118~31.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "docker-runc", rpm: "docker-runc~1.0.0rc10+gitr3981_dc9208a3303f~1.46.1", rls: "SLES12.0" ) )){
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

