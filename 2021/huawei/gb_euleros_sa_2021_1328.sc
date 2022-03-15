if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.1328" );
	script_cve_id( "CVE-2019-5068" );
	script_tag( name: "creation_date", value: "2021-02-22 08:38:59 +0000 (Mon, 22 Feb 2021)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "3.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-06-01 13:15:00 +0000 (Mon, 01 Jun 2020)" );
	script_name( "Huawei EulerOS: Security Advisory for mesa (EulerOS-SA-2021-1328)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP2" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-1328" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1328" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'mesa' package(s) announced via the EulerOS-SA-2021-1328 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An exploitable shared memory permissions vulnerability exists in the functionality of X11 Mesa 3D Graphics Library 19.1.2. An attacker can access the shared memory without any specific permissions to trigger this vulnerability.(CVE-2019-5068)" );
	script_tag( name: "affected", value: "'mesa' package(s) on Huawei EulerOS V2.0SP2." );
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
	if(!isnull( res = isrpmvuln( pkg: "mesa-dri-drivers", rpm: "mesa-dri-drivers~10.6.5~3.20150824.h1", rls: "EULEROS-2.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mesa-filesystem", rpm: "mesa-filesystem~10.6.5~3.20150824.h1", rls: "EULEROS-2.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mesa-libEGL", rpm: "mesa-libEGL~10.6.5~3.20150824.h1", rls: "EULEROS-2.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mesa-libEGL-devel", rpm: "mesa-libEGL-devel~10.6.5~3.20150824.h1", rls: "EULEROS-2.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mesa-libGL", rpm: "mesa-libGL~10.6.5~3.20150824.h1", rls: "EULEROS-2.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mesa-libGL-devel", rpm: "mesa-libGL-devel~10.6.5~3.20150824.h1", rls: "EULEROS-2.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mesa-libGLES", rpm: "mesa-libGLES~10.6.5~3.20150824.h1", rls: "EULEROS-2.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mesa-libgbm", rpm: "mesa-libgbm~10.6.5~3.20150824.h1", rls: "EULEROS-2.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mesa-libglapi", rpm: "mesa-libglapi~10.6.5~3.20150824.h1", rls: "EULEROS-2.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mesa-libxatracker", rpm: "mesa-libxatracker~10.6.5~3.20150824.h1", rls: "EULEROS-2.0SP2" ) )){
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

