if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.3081.1" );
	script_cve_id( "CVE-2017-18258", "CVE-2018-14404", "CVE-2018-14567", "CVE-2018-9251" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-10 01:15:00 +0000 (Thu, 10 Sep 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:3081-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:3081-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20183081-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libxml2' package(s) announced via the SUSE-SU-2018:3081-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libxml2 fixes the following security issues:
CVE-2018-9251: The xz_decomp function allowed remote attackers to cause
 a denial of service (infinite loop) via a crafted XML file that triggers
 LZMA_MEMLIMIT_ERROR, as demonstrated by xmllint (bsc#1088279).

CVE-2018-14567: Prevent denial of service (infinite loop) via a crafted
 XML file that triggers LZMA_MEMLIMIT_ERROR, as demonstrated by xmllint
 (bsc#1105166).

CVE-2018-14404: Prevent NULL pointer dereference in the
 xmlXPathCompOpEval() function when parsing an invalid XPath expression
 in the XPATH_OP_AND or XPATH_OP_OR case leading to a denial of service
 attack (bsc#1102046).

CVE-2017-18258: The xz_head function allowed remote attackers to cause a
 denial of service (memory consumption) via a crafted LZMA file, because
 the decoder functionality did not restrict memory usage to what is
 required for a legitimate file (bsc#1088601)." );
	script_tag( name: "affected", value: "'libxml2' package(s) on OpenStack Cloud Magnum Orchestration 7, SUSE CaaS Platform 3.0, SUSE CaaS Platform ALL, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Software Development Kit 12-SP3." );
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
if(release == "SLES12.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "libxml2-2", rpm: "libxml2-2~2.9.4~46.15.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxml2-2-32bit", rpm: "libxml2-2-32bit~2.9.4~46.15.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxml2-2-debuginfo", rpm: "libxml2-2-debuginfo~2.9.4~46.15.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxml2-2-debuginfo-32bit", rpm: "libxml2-2-debuginfo-32bit~2.9.4~46.15.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxml2-debugsource", rpm: "libxml2-debugsource~2.9.4~46.15.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxml2-doc", rpm: "libxml2-doc~2.9.4~46.15.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxml2-tools", rpm: "libxml2-tools~2.9.4~46.15.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxml2-tools-debuginfo", rpm: "libxml2-tools-debuginfo~2.9.4~46.15.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-libxml2", rpm: "python-libxml2~2.9.4~46.15.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-libxml2-debuginfo", rpm: "python-libxml2-debuginfo~2.9.4~46.15.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-libxml2-debugsource", rpm: "python-libxml2-debugsource~2.9.4~46.15.1", rls: "SLES12.0SP3" ) )){
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

