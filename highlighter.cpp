// See license.txt file

#include <windows.h>
#include <set>

#include <ida.hpp>
#include <idp.hpp>
#include <diskio.hpp>
#include <dbg.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <gdl.hpp>

#pragma comment(lib, "kernel32.lib")

#define PLUGIN_NAME "Highlighter"
#define PLUGIN_VER  "2.0"

static qstrvec_t call_mnemonics;

static int highlighter_enabled = 1;
static int highlighter_color = COLOR_CODNAME;

static const cfgopt_t g_opts[] =
{
    cfgopt_t("HIGHLIGHTER_ENABLED", &highlighter_enabled, 0, 1),
    cfgopt_t("HIGHLIGHTER_COLOR", &highlighter_color, COLOR_DEFAULT, COLOR_FG_MAX),
};

static const int prefix_width = 8;
static const char highlight_prefix[] = { COLOR_INV, ' ', ' ', COLOR_INV, 0 };
static const char call_prefix[] = { COLOR_INV, '=', '>', COLOR_INV, 0 };

// List of executed addresses
typedef std::set<ea_t> easet_t;
static easet_t execset;

//--------------------------------------------------------------------------
static bool highlight_calls(qflow_chart_t *fc, int n, text_t &text)
{
    assert(nullptr != fc);
    if (nullptr == fc)
    {
        return false;
    }

    if (!highlighter_enabled || n >= fc->blocks.size())
    {
        return false;
    }

    gen_disasm_text(text, fc->blocks[n].start_ea, fc->blocks[n].end_ea, false);

    // HTC - fix the bug of original Highlight2 plugin
    for (size_t i = 0; i < text.size(); i++)
    {
        const char *line = text[i].line.c_str();
        size_t len = text[i].line.length();

        // We search for COLOR_INSN in line
        const char *p = line;
        while ((p < line + len) && (COLOR_INSN != *p))
        {
            p++;
        }

        if ((0 == *p) || (p == line + len))
        {
            // Not found COLOR_INSN char
            continue;
        }

        len = line + len - p;
        for (size_t j = 0; j < call_mnemonics.size(); j++)
        {
            const char* instr = call_mnemonics[j].c_str();
            ssize_t instr_len = call_mnemonics[j].length();

            if ((instr_len + 2 < len) &&
                (0 == memcmp(instr, p + 1, instr_len)) &&
                ( COLOR_OFF == p[1 + instr_len]))
            {
                text[i].line[p - line] = highlighter_color;
                // HTC - add "=> " before the call instruction
                if (text[i].line.find("=> ") == qstring::npos)
                {
                    text[i].line.insert(p - line + 1, "=> ");
                }
            }
        }
    }

    return true;
}
//------------------------------------------------------------------------------
static ssize_t idaapi ui_callback(void * /*user_data*/, int code, va_list va)
{
    switch (code)
    {
        case ui_gen_idanode_text:
        {
            qflow_chart_t *fc = va_arg(va, qflow_chart_t *);
            int node = va_arg(va, int);
            text_t *text = va_arg(va, text_t *);
            if ((nullptr != fc) && (nullptr != text))
            {
                return highlight_calls(fc, node, *text);
            }

            break;
        }
    }

    return 0;
}
//------------------------------------------------------------------------------
static void get_call_instructions(void)
{
    if (call_mnemonics.size() > 0)
    {
        call_mnemonics.clear();
    }

    int instruc_count = ph.instruc_end - 1 - ph.instruc_start;

    for (int i = 0; i < instruc_count; i++)
    {
        if ((ph.instruc[i].feature & CF_CALL) == CF_CALL)
        {
            call_mnemonics.push_back(qstring(ph.instruc[i].name));
        }
    }
}

//------------------------------------------------------------------------------
// Read config from ini file in ida user dir\cfg
// HTC - Windows code only, em lam bieng build tren nux va test "nam nam nuon"
//
static void load_config()
{
    char cfg_path[MAXSTR] = { 0 };
    qsnprintf(cfg_path, sizeof(cfg_path), "%s\\%s\\%s%s", get_user_idadir(), CFG_SUBDIR, PLUGIN_NAME, ".ini");
    highlighter_enabled = GetPrivateProfileIntA(PLUGIN_NAME, "Enabled", 1, cfg_path);
    highlighter_color = GetPrivateProfileIntA(PLUGIN_NAME, "Color", COLOR_DEFAULT, cfg_path);
    read_config_file(PLUGIN_NAME, g_opts, qnumber(g_opts));
}

//------------------------------------------------------------------------------
// Write config to ini file in ida user dir\cfg
//
static void save_config()
{
    char cfg_path[MAXSTR] = { 0 };
    char fmt[10] = { 0 };

    qsnprintf(cfg_path, sizeof(cfg_path), "%s\\%s\\%s%s", get_user_idadir(), CFG_SUBDIR, PLUGIN_NAME, ".ini");

    qsnprintf(fmt, sizeof(fmt), "%d", highlighter_enabled);
    WritePrivateProfileStringA(PLUGIN_NAME, "Enabled", fmt, cfg_path);

    qsnprintf(fmt, sizeof(fmt), "%d", highlighter_color);
    WritePrivateProfileStringA(PLUGIN_NAME, "Color", fmt, cfg_path);
}

//------------------------------------------------------------------------------
static void change_options()
{
    static char form[MAXSTR] = { 0 };
    static char *szFmt = "%s Settings\n"
                         " <Enable plugin:C>>\n"
                         " <Select color:b::40::>\n\n"
                         "Hint: to change this permanently, edit %s.cfg.\n\n";
    qsnprintf(form, sizeof(form), szFmt, PLUGIN_NAME, PLUGIN_NAME);

    static const char *items[] =
    {
        "COLOR_DEFAULT",
        "COLOR_REGCMT",
        "COLOR_RPTCMT",
        "COLOR_AUTOCMT",
        "COLOR_INSN",
        "COLOR_DATNAME",
        "COLOR_DNAME",
        "COLOR_DEMNAME",
        "COLOR_SYMBOL",
        "COLOR_CHAR",
        "COLOR_STRING",
        "COLOR_NUMBER",
        "COLOR_VOIDOP",
        "COLOR_CREF",
        "COLOR_DREF",
        "COLOR_CREFTAIL",
        "COLOR_DREFTAIL",
        "COLOR_ERROR",
        "COLOR_PREFIX",
        "COLOR_BINPREF",
        "COLOR_EXTRA",
        "COLOR_ALTOP",
        "COLOR_HIDNAME",
        "COLOR_LIBNAME",
        "COLOR_LOCNAME",
        "COLOR_CODNAME",
        "COLOR_ASMDIR",
        "COLOR_MACRO",
        "COLOR_DSTR",
        "COLOR_DCHAR",
        "COLOR_DNUM",
        "COLOR_KEYWORD",
        "COLOR_REG",
        "COLOR_IMPNAME",
        "COLOR_SEGNAME",
        "COLOR_UNKNAME",
        "COLOR_CNAME",
        "COLOR_UNAME",
        "COLOR_COLLAPSED",
        "COLOR_FG_MAX",
    };

    qstrvec_t list;
    for (int i = 0; i < qnumber(items); i++)
        list.push_back(items[i]);

    int sel = highlighter_color - 1;
    uval_t flags = highlighter_enabled;

    if (ask_form(form, &flags, &list, &sel) > 0)
    {
        highlighter_color = sel + 1;
        highlighter_enabled = flags;
        refresh_idaview_anyway();
    }
}

//-------------------- org code of highligher ----------------------------------

// To manage the processed event of the debugger
struct my_post_events_t : public post_event_visitor_t
{
    virtual ssize_t idaapi handle_post_event(ssize_t code,
                                             int notification_code,
                                             va_list va);
};

static my_post_events_t my_post_events;

//------------------------------------------------------------------------------
static void idaapi get_user_defined_prefix(qstring *buf, ea_t ea, int lnnum, int indent, const char *line)
{
    if (nullptr == buf || nullptr == line)
    {
        return;
    }

    buf->qclear();  // empty prefix by default

    // We want to display the prefix only the lines which
    // contain the instruction itself
    if (indent != -1)
        return;         // a directive

    if (line[0] == '\0')
        return;         // empty line

    if (tag_advance(line, 1)[-1] == ash.cmnt[0])
        return;         // comment line...

    // We don't want the prefix to be printed again for other lines of the
    // same instruction/data. For that we remember the line number
    // and compare it before generating the prefix
    //
    static ea_t old_ea = BADADDR;
    static int old_lnnum = 0;
    if (old_ea == ea && old_lnnum == lnnum)
        return;

    if (execset.find(ea) != execset.end())
        *buf = highlight_prefix;

    // Remember the address and line number we produced the line prefix for:
    old_ea = ea;
    old_lnnum = lnnum;

    // HTC add
    // Prefix call operand with =>
    qstring qline = line;
    tag_remove(&qline);
    for (size_t i = 0; i < call_mnemonics.size(); ++i)
    {
        const char* instr = call_mnemonics[i].c_str();
        ssize_t instr_len = call_mnemonics[i].length();
        if (0 == strnicmp(qline.c_str(), instr, instr_len))
        {
            // We have a call instruction
            *buf = call_prefix;
            break;
        }
    }
}

//------------------------------------------------------------------------------
ssize_t idaapi my_post_events_t::handle_post_event(ssize_t retcode,
                                                   int notification_code,
                                                   va_list va)
{
    switch (notification_code)
    {
        case debugger_t::ev_get_debug_event:
        {
            gdecode_t *code = va_arg(va, gdecode_t *);
            debug_event_t *event = va_arg(va, debug_event_t *);
            if ((nullptr != code) && (nullptr != event))
            {
                if (GDE_ONE_EVENT == *code)    // got an event?
                {
                    execset.insert(event->ea);
                }
            }
        }
        break;
    }

    return retcode;
}

//------------------------------------------------------------------------------
static ssize_t idaapi dbg_callback(void *, int notification_code, va_list)
{
    // We set our debug event handler at the beginning and remove it at the end
    // of a debug session
    switch (notification_code)
    {
        case dbg_process_start:
        case dbg_process_attach:
            set_user_defined_prefix(prefix_width, get_user_defined_prefix);
            register_post_event_visitor(HT_IDD, my_post_events, &PLUGIN);
            break;

        case dbg_process_exit:
            unregister_post_event_visitor(HT_IDD, my_post_events);
            set_user_defined_prefix(0, NULL);
            execset.clear();
            break;
    }

    return 0;
}

//------------------------------------------------------------------------------
// HTC add
// Plugin options action handler
//
struct plugin_options_ah_t : public action_handler_t
{
    static const char* actionName;
    static const char* actionLabel;
    static const char* actionHotkey;

    plugin_options_ah_t() {};

    virtual int idaapi activate(action_activation_ctx_t*) override
    {
        change_options();
        return 0;
    }

    virtual action_state_t idaapi update(action_update_ctx_t*) override
    {
        return AST_ENABLE_ALWAYS;
    }
};

const char *plugin_options_ah_t::actionName = PLUGIN_NAME"::Options";
const char *plugin_options_ah_t::actionLabel = PLUGIN_NAME"...";
const char *plugin_options_ah_t::actionHotkey = "";

plugin_options_ah_t plugin_options_ah = plugin_options_ah_t();
action_desc_t plugin_options_desc = ACTION_DESC_LITERAL(plugin_options_ah_t::actionName,
                                                        plugin_options_ah_t::actionLabel,
                                                        &plugin_options_ah,
                                                        plugin_options_ah_t::actionHotkey,
                                                        nullptr,
                                                        -1);

//------------------------------------------------------------------------------
bool idaapi run(size_t)
{
    info("AUTOHIDE NONE\n"
         "This is the highlighter plugin.\n"
         "It highlights executed instructions if a debug event occurs at them.\n"
         "The plugins is fully automatic and has no parameters.\n\n"
         "Change the color of call instruction in Options - %s...", plugin_options_ah_t::actionLabel);

    return true;
}

//------------------------------------------------------------------------------
int idaapi init(void)
{
    // unload us if text mode, no graph are there
    if (!is_idaq())
        return PLUGIN_SKIP;

    load_config();
    get_call_instructions();
    hook_to_notification_point(HT_UI, ui_callback);

    hook_to_notification_point(HT_DBG, dbg_callback);

    register_action(plugin_options_desc);
    attach_action_to_menu("Options", plugin_options_ah_t::actionName, SETMENU_APP);

    msg("[%s - ver %s] plugin initialized\n", PLUGIN_NAME, PLUGIN_VER);
    return PLUGIN_KEEP;
}

//------------------------------------------------------------------------------
void idaapi term(void)
{
    detach_action_from_menu("Options", plugin_options_ah_t::actionName);
    unregister_action(plugin_options_ah_t::actionName);

    unhook_from_notification_point(HT_DBG, dbg_callback);
    unhook_from_notification_point(HT_UI, ui_callback);

    save_config();
    msg("[%s - ver %s] plugin terminated\n", PLUGIN_NAME, PLUGIN_VER);
}

//------------------------------------------------------------------------------
static const char wanted_name[] = PLUGIN_NAME;
static const char wanted_hotkey[] = "";

//------------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//------------------------------------------------------------------------------
plugin_t PLUGIN =
{
    IDP_INTERFACE_VERSION,
    0,                    // plugin flags
    init,                 // initialize
    term,                 // terminate. this pointer may be NULL.
    run,                  // invoke plugin
    wanted_name,          // long comment about the plugin
                          // it could appear in the status line
                          // or as a hint
    wanted_name,          // multiline help about the plugin
    wanted_name,          // the preferred short name of the plugin
    wanted_hotkey         // the preferred hotkey to run the plugin
};
