if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.2370" );
	script_cve_id( "CVE-2020-11042", "CVE-2020-11526" );
	script_tag( name: "creation_date", value: "2021-09-15 02:24:22 +0000 (Wed, 15 Sep 2021)" );
	script_version( "2021-09-15T02:24:22+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 02:24:22 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-30 02:15:00 +0000 (Sun, 30 Aug 2020)" );
	script_name( "Huawei EulerOS: Security Advisory for freerdp (EulerOS-SA-2021-2370)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP2" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-2370" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2370" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'freerdp' package(s) announced via the EulerOS-SA-2021-2370 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "In FreeRDP greater than 1.1 and before 2.0.0, there is an out-of-bounds read in update_read_icon_info. It allows reading a attacker-defined amount of client memory (32bit unsigned -> 4GB) to an intermediate buffer. This can be used to crash the client or store information for later retrieval. This has been patched in 2.0.0.(CVE-2020-11042)

Iibfreerdp/core/update.c in FreeRDP versions > 1.1 through 2.0.0-rc4 has an Out-of-bounds Read.(CVE-2020-11526)" );
	script_tag( name: "affected", value: "'freerdp' package(s) on Huawei EulerOS V2.0SP2." );
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
if(release == "EULEROS-2.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "freerdp", rpm: "freerdp~1.0.2~6.1.h10", rls: "EULEROS-2.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freerdp-libs", rpm: "freerdp-libs~1.0.2~6.1.h10", rls: "EULEROS-2.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freerdp-plugins", rpm: "freerdp-plugins~1.0.2~6.1.h10", rls: "EULEROS-2.0SP2" ) )){
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

