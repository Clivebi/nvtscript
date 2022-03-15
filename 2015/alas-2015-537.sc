if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120223" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:20:46 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2015-537)" );
	script_tag( name: "insight", value: "ClamAV before 0.98.7 allows remote attackers to cause a denial of service (infinite loop) via a crafted y0da cryptor file. (CVE-2015-2221 )ClamAV before 0.98.7 allows remote attackers to cause a denial of service (infinite loop) via a crafted xz archive file. (CVE-2015-2668 )ClamAV before 0.98.7 allows remote attackers to cause a denial of service (crash) via a crafted petite packed file. (CVE-2015-2222 )The upx decoder in ClamAV before 0.98.7 allows remote attackers to cause a denial of service (crash) via a crafted file. (CVE-2015-2170 )" );
	script_tag( name: "solution", value: "Run yum update clamav to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2015-537.html" );
	script_cve_id( "CVE-2015-2221", "CVE-2015-2170", "CVE-2015-2222", "CVE-2015-2668" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/amazon_linux", "ssh/login/release" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "The remote host is missing an update announced via the referenced Security Advisory." );
	script_copyright( "Copyright (C) 2015 Eero Volotinen" );
	script_family( "Amazon Linux Local Security Checks" );
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
if(release == "AMAZON"){
	if(!isnull( res = isrpmvuln( pkg: "clamd", rpm: "clamd~0.98.7~1.12.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "clamav-db", rpm: "clamav-db~0.98.7~1.12.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "clamav-debuginfo", rpm: "clamav-debuginfo~0.98.7~1.12.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "clamav", rpm: "clamav~0.98.7~1.12.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "clamav-lib", rpm: "clamav-lib~0.98.7~1.12.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "clamav-server", rpm: "clamav-server~0.98.7~1.12.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "clamav-devel", rpm: "clamav-devel~0.98.7~1.12.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "clamav-update", rpm: "clamav-update~0.98.7~1.12.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "clamav-filesystem", rpm: "clamav-filesystem~0.98.7~1.12.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "clamav-server-sysvinit", rpm: "clamav-server-sysvinit~0.98.7~1.12.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "clamav-scanner", rpm: "clamav-scanner~0.98.7~1.12.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "clamav-milter-sysvinit", rpm: "clamav-milter-sysvinit~0.98.7~1.12.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "clamav-data-empty", rpm: "clamav-data-empty~0.98.7~1.12.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "clamav-data", rpm: "clamav-data~0.98.7~1.12.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "clamav-scanner-sysvinit", rpm: "clamav-scanner-sysvinit~0.98.7~1.12.amzn1", rls: "AMAZON" ) )){
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

