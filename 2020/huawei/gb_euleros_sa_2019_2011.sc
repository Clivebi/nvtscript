if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2019.2011" );
	script_cve_id( "CVE-2014-4607" );
	script_tag( name: "creation_date", value: "2020-01-23 12:30:47 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-02-14 15:26:00 +0000 (Fri, 14 Feb 2020)" );
	script_name( "Huawei EulerOS: Security Advisory for grub2 (EulerOS-SA-2019-2011)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP3" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2019-2011" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2011" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'grub2' package(s) announced via the EulerOS-SA-2019-2011 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An integer overflow flaw was found in the way the lzo library decompressed certain archives compressed with the LZO algorithm. An attacker could create a specially crafted LZO-compressed input that, when decompressed by an application using the lzo library, would cause that application to crash or, potentially, execute arbitrary code.(CVE-2014-4607)" );
	script_tag( name: "affected", value: "'grub2' package(s) on Huawei EulerOS V2.0SP3." );
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
	if(!isnull( res = isrpmvuln( pkg: "grub2", rpm: "grub2~2.02~0.64.h7", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-common", rpm: "grub2-common~2.02~0.64.h7", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-efi-x64", rpm: "grub2-efi-x64~2.02~0.64.h7", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-efi-x64-cdboot", rpm: "grub2-efi-x64-cdboot~2.02~0.64.h7", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-efi-x64-modules", rpm: "grub2-efi-x64-modules~2.02~0.64.h7", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-pc", rpm: "grub2-pc~2.02~0.64.h7", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-pc-modules", rpm: "grub2-pc-modules~2.02~0.64.h7", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-tools", rpm: "grub2-tools~2.02~0.64.h7", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-tools-extra", rpm: "grub2-tools-extra~2.02~0.64.h7", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-tools-minimal", rpm: "grub2-tools-minimal~2.02~0.64.h7", rls: "EULEROS-2.0SP3" ) )){
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

