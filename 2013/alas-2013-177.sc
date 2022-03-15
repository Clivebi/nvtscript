if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120561" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:29:37 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2013-177)" );
	script_tag( name: "insight", value: "Multiple flaws were found in Perl. Please see the references for more information." );
	script_tag( name: "solution", value: "Run yum update perl to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2013-177.html" );
	script_cve_id( "CVE-2012-6329", "CVE-2013-1667", "CVE-2012-5526", "CVE-2012-5195" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
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
	if(!isnull( res = isrpmvuln( pkg: "perl-suidperl", rpm: "perl-suidperl~5.10.1~130.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-Pod-Escapes", rpm: "perl-Pod-Escapes~1.04~130.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-libs", rpm: "perl-libs~5.10.1~130.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-version", rpm: "perl-version~0.77~130.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-IO-Compress-Base", rpm: "perl-IO-Compress-Base~2.020~130.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-Archive-Tar", rpm: "perl-Archive-Tar~1.58~130.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-Test-Harness", rpm: "perl-Test-Harness~3.17~130.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-Module-Load", rpm: "perl-Module-Load~0.16~130.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-Compress-Raw-Bzip2", rpm: "perl-Compress-Raw-Bzip2~2.020~130.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-Archive-Extract", rpm: "perl-Archive-Extract~0.38~130.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-IO-Compress-Bzip2", rpm: "perl-IO-Compress-Bzip2~2.020~130.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-IPC-Cmd", rpm: "perl-IPC-Cmd~0.56~130.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-CGI", rpm: "perl-CGI~3.51~130.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-Term-UI", rpm: "perl-Term-UI~0.20~130.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl", rpm: "perl~5.10.1~130.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-ExtUtils-CBuilder", rpm: "perl-ExtUtils-CBuilder~0.27~130.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-Package-Constants", rpm: "perl-Package-Constants~0.02~130.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-Module-Loaded", rpm: "perl-Module-Loaded~0.02~130.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-core", rpm: "perl-core~5.10.1~130.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-Object-Accessor", rpm: "perl-Object-Accessor~0.34~130.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-Compress-Raw-Zlib", rpm: "perl-Compress-Raw-Zlib~2.023~130.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-devel", rpm: "perl-devel~5.10.1~130.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-Module-CoreList", rpm: "perl-Module-CoreList~2.18~130.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-Test-Simple", rpm: "perl-Test-Simple~0.92~130.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-debuginfo", rpm: "perl-debuginfo~5.10.1~130.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-Locale-Maketext-Simple", rpm: "perl-Locale-Maketext-Simple~0.18~130.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-CPANPLUS", rpm: "perl-CPANPLUS~0.88~130.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-Parse-CPAN-Meta", rpm: "perl-Parse-CPAN-Meta~1.40~130.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-IO-Zlib", rpm: "perl-IO-Zlib~1.09~130.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-ExtUtils-Embed", rpm: "perl-ExtUtils-Embed~1.28~130.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-Digest-SHA", rpm: "perl-Digest-SHA~5.47~130.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-Compress-Zlib", rpm: "perl-Compress-Zlib~2.020~130.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-Params-Check", rpm: "perl-Params-Check~0.26~130.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-Time-HiRes", rpm: "perl-Time-HiRes~1.9721~130.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-Module-Build", rpm: "perl-Module-Build~0.3500~130.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-Time-Piece", rpm: "perl-Time-Piece~1.15~130.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-Log-Message", rpm: "perl-Log-Message~0.02~130.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-Module-Pluggable", rpm: "perl-Module-Pluggable~3.90~130.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-CPAN", rpm: "perl-CPAN~1.9402~130.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-ExtUtils-ParseXS", rpm: "perl-ExtUtils-ParseXS~2.2003.0~130.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-Log-Message-Simple", rpm: "perl-Log-Message-Simple~0.04~130.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-Pod-Simple", rpm: "perl-Pod-Simple~3.13~130.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-ExtUtils-MakeMaker", rpm: "perl-ExtUtils-MakeMaker~6.55~130.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-Module-Load-Conditional", rpm: "perl-Module-Load-Conditional~0.30~130.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-IO-Compress-Zlib", rpm: "perl-IO-Compress-Zlib~2.020~130.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-parent", rpm: "perl-parent~0.221~130.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-File-Fetch", rpm: "perl-File-Fetch~0.26~130.17.amzn1", rls: "AMAZON" ) )){
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

