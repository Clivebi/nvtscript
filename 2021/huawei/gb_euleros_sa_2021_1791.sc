if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.1791" );
	script_cve_id( "CVE-2018-10913", "CVE-2018-10914" );
	script_tag( name: "creation_date", value: "2021-05-03 06:20:26 +0000 (Mon, 03 May 2021)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-15 13:28:00 +0000 (Thu, 15 Oct 2020)" );
	script_name( "Huawei EulerOS: Security Advisory for glusterfs (EulerOS-SA-2021-1791)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP3" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-1791" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1791" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'glusterfs' package(s) announced via the EulerOS-SA-2021-1791 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An information disclosure vulnerability was discovered in glusterfs server. An attacker could issue a xattr request via glusterfs FUSE to determine the existence of any file.(CVE-2018-10913)

It was found that an attacker could issue a xattr request via glusterfs FUSE to cause gluster brick process to crash which will result in a remote denial of service. If gluster multiplexing is enabled this will result in a crash of multiple bricks and gluster volumes.(CVE-2018-10914)" );
	script_tag( name: "affected", value: "'glusterfs' package(s) on Huawei EulerOS V2.0SP3." );
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
if(release == "EULEROS-2.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "glusterfs", rpm: "glusterfs~3.8.4~54.15.h3", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glusterfs-api", rpm: "glusterfs-api~3.8.4~54.15.h3", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glusterfs-client-xlators", rpm: "glusterfs-client-xlators~3.8.4~54.15.h3", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glusterfs-fuse", rpm: "glusterfs-fuse~3.8.4~54.15.h3", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glusterfs-libs", rpm: "glusterfs-libs~3.8.4~54.15.h3", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glusterfs-rdma", rpm: "glusterfs-rdma~3.8.4~54.15.h3", rls: "EULEROS-2.0SP3" ) )){
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

