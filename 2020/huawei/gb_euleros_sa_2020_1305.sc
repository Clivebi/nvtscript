if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2020.1305" );
	script_cve_id( "CVE-2019-10063" );
	script_tag( name: "creation_date", value: "2020-03-24 07:29:33 +0000 (Tue, 24 Mar 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-13 10:29:00 +0000 (Mon, 13 May 2019)" );
	script_name( "Huawei EulerOS: Security Advisory for flatpak (EulerOS-SA-2020-1305)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP5" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2020-1305" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1305" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'flatpak' package(s) announced via the EulerOS-SA-2020-1305 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Flatpak before 1.0.8, 1.1.x and 1.2.x before 1.2.4, and 1.3.x before 1.3.1 allows a sandbox bypass. Flatpak versions since 0.8.1 address CVE-2017-5226 by using a seccomp filter to prevent sandboxed apps from using the TIOCSTI ioctl, which could otherwise be used to inject commands into the controlling terminal so that they would be executed outside the sandbox after the sandboxed app exits. This fix was incomplete: on 64-bit platforms, the seccomp filter could be bypassed by an ioctl request number that has TIOCSTI in its 32 least significant bits and an arbitrary nonzero value in its 32 most significant bits, which the Linux kernel would treat as equivalent to TIOCSTI.(CVE-2019-10063)" );
	script_tag( name: "affected", value: "'flatpak' package(s) on Huawei EulerOS V2.0SP5." );
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
if(release == "EULEROS-2.0SP5"){
	if(!isnull( res = isrpmvuln( pkg: "flatpak", rpm: "flatpak~0.8.8~3.h3.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "flatpak-libs", rpm: "flatpak-libs~0.8.8~3.h3.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
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

