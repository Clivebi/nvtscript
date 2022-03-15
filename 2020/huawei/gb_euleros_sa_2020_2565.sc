if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2020.2565" );
	script_cve_id( "CVE-2019-13590", "CVE-2019-8355", "CVE-2019-8356", "CVE-2019-8357" );
	script_tag( name: "creation_date", value: "2020-12-15 07:19:35 +0000 (Tue, 15 Dec 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-24 15:16:00 +0000 (Thu, 24 Jun 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for sox (EulerOS-SA-2020-2565)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP5" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2020-2565" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-2565" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'sox' package(s) announced via the EulerOS-SA-2020-2565 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An issue was discovered in SoX 14.4.2. In xmalloc.h, there is an integer overflow on the result of multiplication fed into the lsx_valloc macro that wraps malloc. When the buffer is allocated, it is smaller than expected, leading to a heap-based buffer overflow in channels_start in remix.c.(CVE-2019-8355)

An issue was discovered in SoX 14.4.2. One of the arguments to bitrv2 in fft4g.c is not guarded, such that it can lead to write access outside of the statically declared array, aka a stack-based buffer overflow.(CVE-2019-8356)

An issue was discovered in SoX 14.4.2. lsx_make_lpf in effect_i_dsp.c allows a NULL pointer dereference.(CVE-2019-8357)

An issue was discovered in libsox.a in SoX 14.4.2. In sox-fmt.h (startread function), there is an integer overflow on the result of integer addition (wraparound to 0) fed into the lsx_calloc macro that wraps malloc. When a NULL pointer is returned, it is used without a prior check that it is a valid pointer, leading to a NULL pointer dereference on lsx_readbuf in formats_i.c.(CVE-2019-13590)" );
	script_tag( name: "affected", value: "'sox' package(s) on Huawei EulerOS V2.0SP5." );
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
	if(!isnull( res = isrpmvuln( pkg: "sox", rpm: "sox~14.4.1~6.h3.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
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

