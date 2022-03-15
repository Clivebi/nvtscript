if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111084" );
	script_version( "2021-02-02T12:11:39+0000" );
	script_tag( name: "last_modification", value: "2021-02-02 12:11:39 +0000 (Tue, 02 Feb 2021)" );
	script_tag( name: "creation_date", value: "2016-02-04 09:00:00 +0100 (Thu, 04 Feb 2016)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Source Control Management (SCM) Files Accessible" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 SCHUTZWERK GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The script attempts to identify files of a SCM accessible
  at the webserver." );
	script_tag( name: "insight", value: "Currently the script is checking for files of the following SCM:

  - Git (.git)

  - Mercurial (.hg)

  - Bazaar (.bzr)

  - CVS (CVS/Root, CVS/Entries)

  - Subversion (.svn)" );
	script_tag( name: "vuldetect", value: "Check the response if SCM files are accessible." );
	script_tag( name: "impact", value: "Based on the information provided in this files an attacker might
  be able to gather additional info about the structure of the system and its applications." );
	script_tag( name: "solution", value: "Restrict access to the SCM files for authorized systems only." );
	script_xref( name: "URL", value: "http://pen-testing.sans.org/blog/pen-testing/2012/12/06/all-your-svn-are-belong-to-us" );
	script_xref( name: "URL", value: "https://github.com/anantshri/svn-extractor" );
	script_xref( name: "URL", value: "https://blog.skullsecurity.org/2012/using-git-clone-to-get-pwn3d" );
	script_xref( name: "URL", value: "https://blog.netspi.com/dumping-git-data-from-misconfigured-web-servers/" );
	script_xref( name: "URL", value: "http://resources.infosecinstitute.com/hacking-svn-git-and-mercurial/" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_timeout( 600 );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
files = make_array( "/.git/HEAD", "^ref: refs/", "/.git/FETCH_HEAD", "^[a-f0-9]{40}\\s+(not-for-merge\\s+)?branch ", "/.git/ORIG_HEAD", "^[a-f0-9]{40}$", "/.git/logs/HEAD", "^[a-f0-9]{40} [a-f0-9]{40} ", "/.git/config", "^\\[(core|receive|(remote|branch) .+)\\]$", "/.git/info/refs", "^[a-f0-9]{40}\\s+refs/", "/.git/description", "Unnamed repository", "/.git/info/exclude", "git ls-files", "/.hg/requires", "^(revlogv1|store|fncache|shared|dotencode|parentdelta|generaldelta|sparse-revlog|revlog-compression-zstd)$", "/.hg/hgrc", "^(\\[(paths|web|hooks|ui)\\]$|# example repository config)", "/.hg/branch", "^(default|production|stable|release)$", "/.hg/undo.branch", "^(default|production|stable|release)$", "/.hg/branch.cache", "^[a-f0-9]{40} [0-9a-zA-Z.-]+$", "/.hg/branchheads.cache", "^[a-f0-9]{40} [0-9a-zA-Z.-]+$", "/.hg/last-message.txt", "^no message$", "/.hg/undo.desc", "^(push-response|pull|commit|serve|remote:ssh:[a-z0-9.]+)$", "/CVS/Root", "^:(local|ext|fork|server|gserver|kserver|pserver):[^\\r\\n]+/", "/RCS/", "<a href=\"[^\"]+,v\"> ?[^,]+,v</a>", "/.bzr/README", "This is a Bazaar control directory.", "/.bzr/branch-format", "Bazaar-NG meta directory", "/.svn/dir-prop-base", "svn:ignore", "/.svn/all-wcprops", "svn:wc:", "/.svn/wc.db", "SQLite format", "/CVS/Entries", "^D?/.+/.*/.*/.*/.*", "/.hg/sourcetreeconfig", "^((savedIncoming|lastUsedView|savedOutgoing|disablerecursiveoperations|autorefreshremotes)=[01]$|(remoteProjectLink[0-9]+\\.(identifier|username|baseUrl|remoteName|type)|lastCheckedRemotes)=)", "/.git/sourcetreeconfig", "^((savedIncoming|lastUsedView|savedOutgoing|disablerecursiveoperations|autorefreshremotes)=[01]$|(remoteProjectLink[0-9]+\\.(identifier|username|baseUrl|remoteName|type)|lastCheckedRemotes)=)" );
report = "The following SCM files/folders were identified:\n";
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	for file in keys( files ) {
		url = dir + file;
		pattern = files[file];
		res = http_get_cache( port: port, item: url );
		if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
			continue;
		}
		res = http_extract_body_from_response( data: res );
		res = chomp( res );
		if(!res){
			continue;
		}
		if(egrep( string: res, pattern: pattern, icase: FALSE )){
			report += "\n" + http_report_vuln_url( port: port, url: url, url_only: TRUE );
			VULN = TRUE;
		}
	}
}
if(VULN){
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

