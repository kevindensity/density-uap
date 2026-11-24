---- MODULE Kernel_TTrace_1795302917 ----
EXTENDS Sequences, Kernel_TEConstants, TLCExt, Toolbox, Naturals, TLC, Kernel

_expression ==
    LET Kernel_TEExpression == INSTANCE Kernel_TEExpression
    IN Kernel_TEExpression!expression
----

_trace ==
    LET Kernel_TETrace == INSTANCE Kernel_TETrace
    IN Kernel_TETrace!trace
----

_inv ==
    ~(
        TLCGet("level") = Len(_TETrace)
        /\
        consumed = (TRUE)
        /\
        eff = ("emitted")
        /\
        bound = ({})
        /\
        finalBy = ("none")
        /\
        revoked = (FALSE)
        /\
        grant = ("consumed")
        /\
        emissions = (2)
        /\
        snap = (<<"consumed", "released", TRUE, FALSE>>)
    )
----

_init ==
    /\ revoked = _TETrace[1].revoked
    /\ eff = _TETrace[1].eff
    /\ consumed = _TETrace[1].consumed
    /\ emissions = _TETrace[1].emissions
    /\ bound = _TETrace[1].bound
    /\ finalBy = _TETrace[1].finalBy
    /\ snap = _TETrace[1].snap
    /\ grant = _TETrace[1].grant
----

_next ==
    /\ \E i,j \in DOMAIN _TETrace:
        /\ \/ /\ j = i + 1
              /\ i = TLCGet("level")
        /\ revoked  = _TETrace[i].revoked
        /\ revoked' = _TETrace[j].revoked
        /\ eff  = _TETrace[i].eff
        /\ eff' = _TETrace[j].eff
        /\ consumed  = _TETrace[i].consumed
        /\ consumed' = _TETrace[j].consumed
        /\ emissions  = _TETrace[i].emissions
        /\ emissions' = _TETrace[j].emissions
        /\ bound  = _TETrace[i].bound
        /\ bound' = _TETrace[j].bound
        /\ finalBy  = _TETrace[i].finalBy
        /\ finalBy' = _TETrace[j].finalBy
        /\ snap  = _TETrace[i].snap
        /\ snap' = _TETrace[j].snap
        /\ grant  = _TETrace[i].grant
        /\ grant' = _TETrace[j].grant

\* Uncomment the ASSUME below to write the states of the error trace
\* to the given file in Json format. Note that you can pass any tuple
\* to `JsonSerialize`. For example, a sub-sequence of _TETrace.
    \* ASSUME
    \*     LET J == INSTANCE Json
    \*         IN J!JsonSerialize("Kernel_TTrace_1795302917.json", _TETrace)

=============================================================================

 Note that you can extract this module `Kernel_TEExpression`
  to a dedicated file to reuse `expression` (the module in the 
  dedicated `Kernel_TEExpression.tla` file takes precedence 
  over the module `Kernel_TEExpression` below).

---- MODULE Kernel_TEExpression ----
EXTENDS Sequences, Kernel_TEConstants, TLCExt, Toolbox, Naturals, TLC, Kernel

expression == 
    [
        \* To hide variables of the `Kernel` spec from the error trace,
        \* remove the variables below.  The trace will be written in the order
        \* of the fields of this record.
        revoked |-> revoked
        ,eff |-> eff
        ,consumed |-> consumed
        ,emissions |-> emissions
        ,bound |-> bound
        ,finalBy |-> finalBy
        ,snap |-> snap
        ,grant |-> grant
        
        \* Put additional constant-, state-, and action-level expressions here:
        \* ,_stateNumber |-> _TEPosition
        \* ,_revokedUnchanged |-> revoked = revoked'
        
        \* Format the `revoked` variable as Json value.
        \* ,_revokedJson |->
        \*     LET J == INSTANCE Json
        \*     IN J!ToJson(revoked)
        
        \* Lastly, you may build expressions over arbitrary sets of states by
        \* leveraging the _TETrace operator.  For example, this is how to
        \* count the number of times a spec variable changed up to the current
        \* state in the trace.
        \* ,_revokedModCount |->
        \*     LET F[s \in DOMAIN _TETrace] ==
        \*         IF s = 1 THEN 0
        \*         ELSE IF _TETrace[s].revoked # _TETrace[s-1].revoked
        \*             THEN 1 + F[s-1] ELSE F[s-1]
        \*     IN F[_TEPosition - 1]
    ]

=============================================================================



Parsing and semantic processing can take forever if the trace below is long.
 In this case, it is advised to uncomment the module below to deserialize the
 trace from a generated binary file.

\*
\*---- MODULE Kernel_TETrace ----
\*EXTENDS IOUtils, Kernel_TEConstants, TLC, Kernel
\*
\*trace == IODeserialize("Kernel_TTrace_1795302917.bin", TRUE)
\*
\*=============================================================================
\*

---- MODULE Kernel_TETrace ----
EXTENDS Kernel_TEConstants, TLC, Kernel

trace == 
    <<
    ([consumed |-> FALSE,eff |-> "planned",bound |-> {},finalBy |-> "none",revoked |-> FALSE,grant |-> "none",emissions |-> 0,snap |-> <<>>]),
    ([consumed |-> FALSE,eff |-> "authorized",bound |-> {},finalBy |-> "none",revoked |-> FALSE,grant |-> "issued",emissions |-> 0,snap |-> <<>>]),
    ([consumed |-> TRUE,eff |-> "released",bound |-> {},finalBy |-> "none",revoked |-> FALSE,grant |-> "consumed",emissions |-> 0,snap |-> <<>>]),
    ([consumed |-> TRUE,eff |-> "released",bound |-> {},finalBy |-> "none",revoked |-> FALSE,grant |-> "consumed",emissions |-> 0,snap |-> <<"consumed", "released", TRUE, FALSE>>]),
    ([consumed |-> TRUE,eff |-> "emitted",bound |-> {},finalBy |-> "none",revoked |-> FALSE,grant |-> "consumed",emissions |-> 1,snap |-> <<"consumed", "released", TRUE, FALSE>>]),
    ([consumed |-> TRUE,eff |-> "released",bound |-> {},finalBy |-> "none",revoked |-> FALSE,grant |-> "consumed",emissions |-> 1,snap |-> <<"consumed", "released", TRUE, FALSE>>]),
    ([consumed |-> TRUE,eff |-> "emitted",bound |-> {},finalBy |-> "none",revoked |-> FALSE,grant |-> "consumed",emissions |-> 2,snap |-> <<"consumed", "released", TRUE, FALSE>>])
    >>
----


=============================================================================

---- MODULE Kernel_TEConstants ----
EXTENDS Kernel

CONSTANTS c1, c2

=============================================================================

---- CONFIG Kernel_TTrace_1795302917 ----
CONSTANTS
    Candidates = { c1 , c2 }
    DurableLog = TRUE
    c2 = c2
    c1 = c1

INVARIANT
    _inv

CHECK_DEADLOCK
    \* CHECK_DEADLOCK off because of PROPERTY or INVARIANT above.
    FALSE

INIT
    _init

NEXT
    _next

CONSTANT
    _TETrace <- _trace

ALIAS
    _expression
=============================================================================
\* Generated on Sat Nov 21 23:15:19 UTC 2026