# SourceMapper

**Extender -> Extensions -> Add -> Select file -> SourceMapper/release/SourceMapper-x.x.x.jar**

As you use Burp Suite, SourceMapper passively scans JavaScript for source map comments. When it finds a possible source map, it will create an issue within Burp and add the location of the source map to Burp's site map. 

When you `Passively scan this branch` from Burp Suite's `Site map`, Burp will request any .js.map files that SourceMapper found. SourceMapper will then analyse these in an attempt to extract the source code.

Head over to the "SourceMapper" tab to view any successfully extracted source code.

Future features:
 - Export to file system
 - Search